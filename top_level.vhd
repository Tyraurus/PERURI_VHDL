--------------------------------------------------------------------------------
-- top_level.vhd -- Hardware-Isolated Security CU (hardware-agnostic)
--
-- Default generic untuk DE10-Nano (Cyclone V, clock 50 MHz, KEY0 aktif rendah).
-- Hanya ieee.std_logic_1164 / ieee.numeric_std; tanpa IP/primitif vendor.
--
-- Telemetri (nama sinyal mengikuti proposal):
--   request_start : permintaan autentikasi. DIHITUNG LANGSUNG dari sinyal yang
--                   sama dengan yang masuk ke gate, sehingga tidak ada request
--                   yang lolos tanpa terhitung (V12).
--   auth_fail     : kegagalan autentikasi dari blok auth hardware
--   crypto_busy   : status crypto sibuk dari blok auth hardware
--
-- Pemetaan port (usulan DE10-Nano, atur di pin assignment Quartus):
--   clk             <- FPGA_CLK1_50 (50 MHz)
--   rst_in          <- KEY[0] SAJA (aktif rendah). Jangan sambungkan ke GPIO/HPS:
--                      pin ini adalah satu-satunya trusted reset.
--   request_start   <- start request dari host/auth engine (untrusted)
--   auth_fail       <- GPIO / auth engine
--   crypto_busy     <- GPIO / auth engine
--   protected_start -> start ke protected resource (sudah digate)
--   crypto_enable   -> enable protected block (hardwired)
--   allow_access    -> LED[3] / GPIO
--   state_code      -> LED[1:0] (observasi saja)
--   lockdown        -> LED[2]   (latched)
--
-- Tidak ada port yang dapat meng-clear/disable security_cu selain rst_in.
-- Catatan: request_start yang ditahan >1 siklus dihitung sebagai 1 event
-- (rising edge), sementara gate meneruskan level-nya apa adanya.
--------------------------------------------------------------------------------
library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity top_level is
  generic (
    CLK_FREQ_HZ    : positive := 50_000_000;  -- dokumentasi; window ditentukan WINDOW_CYCLES
    WINDOW_CYCLES  : positive := 500_000;     -- 10 ms @ 50 MHz
    RST_ACTIVE_LOW : boolean  := true;        -- true: KEY0 (Terasic); false: aktif tinggi
    SYNC_INPUTS    : boolean  := true;        -- 2-FF sync untuk telemetri asinkron
    CNT_WIDTH      : positive range 1 to 30 := 16;
    BUSY_WIDTH     : positive range 1 to 30 := 20;
    RATE_TH        : natural  := 16;          -- ~1600 req/s
    FAIL_TH        : natural  := 4;
    FAIL_HARD      : natural  := 8;
    BUSY_TH        : natural  := 250_000;     -- 50% busy
    K_SUSPICIOUS   : positive range 1 to 255 := 2;
    K_LOCK         : positive range 1 to 255 := 3;
    CLEAN_WINDOWS  : positive range 1 to 255 := 4
  );
  port (
    clk             : in  std_logic;
    rst_in          : in  std_logic;
    -- telemetri (untrusted -> trusted, satu arah)
    request_start   : in  std_logic;
    auth_fail       : in  std_logic;
    crypto_busy     : in  std_logic;
    -- ke protected resource
    protected_start : out std_logic;
    crypto_enable   : out std_logic;
    allow_access    : out std_logic;
    -- observasi saja
    state_code      : out std_logic_vector(1 downto 0);
    lockdown        : out std_logic;
    window_valid    : out std_logic;
    blocked         : out std_logic
  );
end entity;

architecture rtl of top_level is
  signal rst_raw, rst_meta, rst_sync : std_logic := '1';

  signal req_m, fail_m, busy_m : std_logic := '0';
  signal req_s, fail_s, busy_s : std_logic := '0';
  signal req_d, fail_d         : std_logic := '0';
  signal req_ev, fail_ev       : std_logic;

  -- nama sinyal dipertahankan agar mudah di-probe SignalTap
  signal req_count, fail_count : unsigned(CNT_WIDTH-1  downto 0);
  signal busy_count            : unsigned(BUSY_WIDTH-1 downto 0);
  signal win_valid_s           : std_logic;
  signal allow_s               : std_logic;
begin
  ------------------------------------------------------------------
  -- Konfigurasi polaritas reset -> internal aktif tinggi
  ------------------------------------------------------------------
  rst_raw <= (not rst_in) when RST_ACTIVE_LOW else rst_in;

  -- Reset synchronizer: assert asinkron, release sinkron (trusted reset fisik)
  process (clk, rst_raw)
  begin
    if rst_raw = '1' then
      rst_meta <= '1';
      rst_sync <= '1';
    elsif rising_edge(clk) then
      rst_meta <= '0';
      rst_sync <= rst_meta;
    end if;
  end process;

  ------------------------------------------------------------------
  -- Input telemetri: (opsional) sync 2-FF + rising-edge detect agar
  -- pulse yang ditahan beberapa siklus tetap dihitung sebagai 1 event.
  ------------------------------------------------------------------
  process (clk)
  begin
    if rising_edge(clk) then
      if SYNC_INPUTS then
        req_m  <= request_start; req_s  <= req_m;
        fail_m <= auth_fail;     fail_s <= fail_m;
        busy_m <= crypto_busy;   busy_s <= busy_m;
      else
        req_s <= request_start; fail_s <= auth_fail; busy_s <= crypto_busy;
      end if;
      req_d  <= req_s;
      fail_d <= fail_s;
    end if;
  end process;
  req_ev  <= req_s  and (not req_d);
  fail_ev <= fail_s and (not fail_d);

  ------------------------------------------------------------------
  -- Telemetry extractor + window counters
  ------------------------------------------------------------------
  u_window : entity work.event_window
    generic map (WINDOW_CYCLES => WINDOW_CYCLES,
                 CNT_WIDTH => CNT_WIDTH, BUSY_WIDTH => BUSY_WIDTH)
    port map (clk => clk, rst => rst_sync,
              req_pulse => req_ev, fail_pulse => fail_ev, busy => busy_s,
              req_count => req_count, fail_count => fail_count,
              busy_count => busy_count, window_valid => win_valid_s);

  ------------------------------------------------------------------
  -- Security CU (trusted domain). Tidak ada port tulis dari host.
  ------------------------------------------------------------------
  u_cu : entity work.security_cu
    generic map (RATE_TH => RATE_TH, FAIL_TH => FAIL_TH, FAIL_HARD => FAIL_HARD,
                 BUSY_TH => BUSY_TH, K_SUSPICIOUS => K_SUSPICIOUS,
                 K_LOCK => K_LOCK, CLEAN_WINDOWS => CLEAN_WINDOWS)
    port map (clk => clk, rst => rst_sync, window_valid => win_valid_s,
              req_count => req_count, fail_count => fail_count,
              busy_count => busy_count,
              state_code => state_code, lockdown => lockdown,
              allow_access => allow_s, crypto_enable => crypto_enable);

  ------------------------------------------------------------------
  -- Enforcement gate (request_start mentah, tanpa latensi/bypass)
  ------------------------------------------------------------------
  u_gate : entity work.protected_gate
    port map (request_start => request_start, allow_access => allow_s,
              protected_start => protected_start, blocked => blocked);

  allow_access <= allow_s;
  window_valid <= win_valid_s;
end architecture;
