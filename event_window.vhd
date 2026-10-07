--------------------------------------------------------------------------------
-- event_window.vhd
-- Fixed-window telemetry counters (R1, R2).
-- Menghitung req / fail / busy dalam window WINDOW_CYCLES clock. Pada akhir
-- window, hasil di-latch ke output dan window_valid = '1' selama SATU siklus
-- (hasil stabil sampai window berikutnya). Counter saturating (tidak wrap).
-- Hanya IEEE standar; tanpa primitif vendor.
--------------------------------------------------------------------------------
library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity event_window is
  generic (
    WINDOW_CYCLES : positive := 500_000;  -- 10 ms @ 50 MHz
    CNT_WIDTH     : positive range 1 to 30 := 16;  -- lebar req_count / fail_count
    BUSY_WIDTH    : positive range 1 to 30 := 20   -- harus >= log2(WINDOW_CYCLES+1)
  );
  port (
    clk          : in  std_logic;
    rst          : in  std_logic;         -- aktif tinggi, sinkron
    req_pulse    : in  std_logic;         -- 1 siklus per request (dari request_start)
    fail_pulse   : in  std_logic;         -- 1 siklus per auth_fail
    busy         : in  std_logic;         -- level: crypto_busy
    req_count    : out unsigned(CNT_WIDTH-1  downto 0);
    fail_count   : out unsigned(CNT_WIDTH-1  downto 0);
    busy_count   : out unsigned(BUSY_WIDTH-1 downto 0);
    window_valid : out std_logic          -- 1 siklus: statistik siap dibaca
  );
end entity;

architecture rtl of event_window is
  constant MAX_CNT  : unsigned(CNT_WIDTH-1  downto 0) := (others => '1');
  constant MAX_BUSY : unsigned(BUSY_WIDTH-1 downto 0) := (others => '1');

  signal cyc                 : natural range 0 to WINDOW_CYCLES-1 := 0;
  signal req_acc, fail_acc   : unsigned(CNT_WIDTH-1  downto 0) := (others => '0');
  signal busy_acc            : unsigned(BUSY_WIDTH-1 downto 0) := (others => '0');
  signal req_q, fail_q       : unsigned(CNT_WIDTH-1  downto 0) := (others => '0');
  signal busy_q              : unsigned(BUSY_WIDTH-1 downto 0) := (others => '0');
  signal valid_q             : std_logic := '0';
begin
  -- Validasi generic (aktif saat simulasi/elaborasi)
  assert 2**BUSY_WIDTH > WINDOW_CYCLES
    report "BUSY_WIDTH terlalu kecil untuk WINDOW_CYCLES" severity failure;

  req_count    <= req_q;
  fail_count   <= fail_q;
  busy_count   <= busy_q;
  window_valid <= valid_q;

  process (clk)
    variable v_req, v_fail : unsigned(CNT_WIDTH-1  downto 0);
    variable v_busy        : unsigned(BUSY_WIDTH-1 downto 0);
  begin
    if rising_edge(clk) then
      valid_q <= '0';
      if rst = '1' then
        cyc      <= 0;
        req_acc  <= (others => '0');
        fail_acc <= (others => '0');
        busy_acc <= (others => '0');
        req_q    <= (others => '0');
        fail_q   <= (others => '0');
        busy_q   <= (others => '0');
      else
        -- nilai berikutnya (termasuk event pada siklus ini, jadi event yang
        -- bersamaan dengan tick tetap terhitung di window yang berakhir)
        v_req := req_acc; v_fail := fail_acc; v_busy := busy_acc;
        if req_pulse  = '1' and v_req  /= MAX_CNT  then v_req  := v_req  + 1; end if;
        if fail_pulse = '1' and v_fail /= MAX_CNT  then v_fail := v_fail + 1; end if;
        if busy       = '1' and v_busy /= MAX_BUSY then v_busy := v_busy + 1; end if;

        if cyc = WINDOW_CYCLES-1 then          -- window tick
          req_q    <= v_req;
          fail_q   <= v_fail;
          busy_q   <= v_busy;
          valid_q  <= '1';
          req_acc  <= (others => '0');
          fail_acc <= (others => '0');
          busy_acc <= (others => '0');
          cyc      <= 0;
        else
          req_acc  <= v_req;
          fail_acc <= v_fail;
          busy_acc <= v_busy;
          cyc      <= cyc + 1;
        end if;
      end if;
    end if;
  end process;
end architecture;
