--------------------------------------------------------------------------------
-- security_cu.vhd
-- Detection FSM bertingkat + sticky lockdown (R3, R4, R5).
--
-- TRUST BOUNDARY: entity ini TIDAK punya port tulis/clear/disable dari
-- software. Satu-satunya cara keluar dari LOCKDOWN adalah rst (trusted
-- physical reset, diturunkan dari pin KEY0 di top_level).
-- allow_access hanya di-drive oleh entity ini (single driver).
--
-- Skor anomali per window (0..4):
--   +2 jika fail_count >= FAIL_TH
--   +1 jika req_count  >= RATE_TH
--   +1 jika busy_count >= BUSY_TH
--
-- Transisi (dievaluasi hanya saat window_valid = '1'):
--   NORMAL     -> WATCH      : score >= 1
--   WATCH      -> SUSPICIOUS : score >= 2 selama K_SUSPICIOUS window berturut
--   WATCH      -> NORMAL     : score = 0 selama CLEAN_WINDOWS window berturut
--   SUSPICIOUS -> LOCKDOWN   : score >= 3, ATAU fail_count >= FAIL_HARD,
--                              ATAU score >= 2 selama K_LOCK window berturut
--   SUSPICIOUS -> WATCH      : score = 0 selama CLEAN_WINDOWS window berturut
--   LOCKDOWN   -> (tetap)    : absorbing; hanya rst yang mengembalikan NORMAL
--
-- Latensi (dari window pertama yang terdeteksi):
--   serangan berat (score>=3, K_SUSPICIOUS=2) : 4 window
--   serangan persisten ringan (score=2)       : 1 + K_SUSPICIOUS + K_LOCK window
--
-- state_code: "00" NORMAL, "01" WATCH, "10" SUSPICIOUS, "11" LOCKDOWN
--------------------------------------------------------------------------------
library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity security_cu is
  generic (
    RATE_TH       : natural := 16;        -- request/window (10 ms)
    FAIL_TH       : natural := 4;         -- failure/window -> +2 skor
    FAIL_HARD     : natural := 8;         -- failure/window -> lockdown dari SUSPICIOUS
    BUSY_TH       : natural := 250_000;   -- ~50% dari 500_000 siklus window
    K_SUSPICIOUS  : positive range 1 to 255 := 2;
    K_LOCK        : positive range 1 to 255 := 3;
    CLEAN_WINDOWS : positive range 1 to 255 := 4
  );
  port (
    clk           : in  std_logic;
    rst           : in  std_logic;        -- trusted reset, aktif tinggi
    window_valid  : in  std_logic;
    req_count     : in  unsigned;
    fail_count    : in  unsigned;
    busy_count    : in  unsigned;
    state_code    : out std_logic_vector(1 downto 0);  -- observasi saja
    lockdown      : out std_logic;                     -- observasi saja
    allow_access  : out std_logic;                     -- hardwired enforcement
    crypto_enable : out std_logic                      -- hardwired enforcement
  );
end entity;

architecture rtl of security_cu is
  type sec_state_t is (NORMAL, WATCH, SUSPICIOUS, LOCKDOWN);
  signal sec_state  : sec_state_t := NORMAL;
  signal lock_latch : std_logic   := '0';
  signal persist    : natural range 0 to 255 := 0;  -- window "buruk" berturut
  signal clean      : natural range 0 to 255 := 0;  -- window "bersih" berturut

  signal score      : natural range 0 to 4;
  signal fail_hard_hit, fail_hit, rate_hit, busy_hit : boolean;

  function b2i(b : boolean) return natural is
  begin
    if b then return 1; else return 0; end if;
  end function;
begin
  -- Validasi generic: threshold 0 membuat kondisi selalu benar (alarm permanen)
  assert RATE_TH > 0 and FAIL_TH > 0 and BUSY_TH > 0
    report "Threshold 0 tidak valid (kondisi selalu terpenuhi)" severity failure;
  assert FAIL_HARD >= FAIL_TH
    report "FAIL_HARD sebaiknya >= FAIL_TH" severity warning;

  -- Skor anomali (kombinasional murni, komparator konstanta)
  fail_hit      <= to_integer(fail_count) >= FAIL_TH;
  rate_hit      <= to_integer(req_count)  >= RATE_TH;
  busy_hit      <= to_integer(busy_count) >= BUSY_TH;
  score         <= (2 * b2i(fail_hit)) + b2i(rate_hit) + b2i(busy_hit);
  fail_hard_hit <= to_integer(fail_count) >= FAIL_HARD;

  process (clk)
  begin
    if rising_edge(clk) then
      if rst = '1' then
        sec_state  <= NORMAL;
        lock_latch <= '0';
        persist    <= 0;
        clean      <= 0;
      elsif window_valid = '1' then
        case sec_state is

          when NORMAL =>
            persist <= 0; clean <= 0;
            if score >= 1 then sec_state <= WATCH; end if;

          when WATCH =>
            if score >= 2 then                       -- window buruk
              clean <= 0;
              if persist + 1 >= K_SUSPICIOUS then
                sec_state <= SUSPICIOUS; persist <= 0;
              else
                persist <= persist + 1;
              end if;
            elsif score = 0 then                     -- window bersih -> decay
              persist <= 0;
              if clean + 1 >= CLEAN_WINDOWS then
                sec_state <= NORMAL; clean <= 0;
              else
                clean <= clean + 1;
              end if;
            else                                     -- score = 1: tahan
              persist <= 0; clean <= 0;
            end if;

          when SUSPICIOUS =>
            if score >= 3 or fail_hard_hit then      -- serangan berat
              sec_state  <= LOCKDOWN;
              lock_latch <= '1';                     -- latch dipasang bersamaan
            elsif score >= 2 then                    -- persisten ringan
              clean <= 0;
              if persist + 1 >= K_LOCK then
                sec_state  <= LOCKDOWN;
                lock_latch <= '1';
              else
                persist <= persist + 1;
              end if;
            elsif score = 0 then                     -- bersih -> turun ke WATCH
              persist <= 0;
              if clean + 1 >= CLEAN_WINDOWS then
                sec_state <= WATCH; clean <= 0;
              else
                clean <= clean + 1;
              end if;
            else                                     -- score = 1: tahan
              persist <= 0; clean <= 0;
            end if;

          when LOCKDOWN =>                           -- absorbing / sticky
            sec_state  <= LOCKDOWN;
            lock_latch <= '1';

        end case;
      end if;
    end if;
  end process;

  -- Output observasi
  with sec_state select state_code <=
    "00" when NORMAL,
    "01" when WATCH,
    "10" when SUSPICIOUS,
    "11" when LOCKDOWN;

  lockdown      <= lock_latch;
  -- Enforcement: satu-satunya driver allow_access. Berbasis lock_latch
  -- (flop terpisah dari sec_state) agar jalur kill sederhana dan mudah diaudit.
  allow_access  <= not lock_latch;
  crypto_enable <= not lock_latch;
end architecture;
