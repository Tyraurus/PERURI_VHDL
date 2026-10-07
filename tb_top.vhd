--------------------------------------------------------------------------------
-- tb_top.vhd : self-checking testbench (window dikecilkan menjadi 100 siklus).
-- Cakupan: V1 reset, V2 normal, V4 failure tinggi -> LOCKDOWN (+ latensi),
-- V5 post-lock block (100%), V7 sticky, V8 trusted reset,
-- V11 persisten di bawah FAIL_HARD -> LOCKDOWN via K_LOCK, V12 (request
-- terhitung hanya dari request_start). Sesuai VHDL-93; VHDL-2008 juga bisa.
-- Compile order: event_window, security_cu, protected_gate, top_level, tb_top
--------------------------------------------------------------------------------
library ieee;
use ieee.std_logic_1164.all;

entity tb_top is end entity;

architecture sim of tb_top is
  constant T      : time    := 20 ns;   -- 50 MHz
  constant WIN    : natural := 100;     -- siklus per window (simulasi)
  constant K_SUSP : natural := 2;
  constant K_LK   : natural := 3;

  type mode_t is (IDLE, NORMAL_M, ATTACK_M, PERSIST_M);
  signal mode : mode_t := IDLE;

  signal clk    : std_logic := '0';
  signal rst_in : std_logic := '0';     -- aktif rendah: reset awal
  signal rs, fail, busy : std_logic := '0';
  signal ps, ce, aa, lock, wv, blk : std_logic;
  signal sc     : std_logic_vector(1 downto 0);
  signal stop   : boolean := false;

  signal measure    : boolean := false;
  signal win_cnt    : natural := 0;
  signal n_req_post, n_blk_post, n_ps_post : natural := 0;
begin
  clk <= not clk after T/2 when not stop else clk;

  dut : entity work.top_level
    generic map (WINDOW_CYCLES => WIN, RATE_TH => 5, FAIL_TH => 2, FAIL_HARD => 6,
                 BUSY_TH => 50, K_SUSPICIOUS => K_SUSP, K_LOCK => K_LK,
                 CLEAN_WINDOWS => 2)
    port map (clk => clk, rst_in => rst_in,
              request_start => rs, auth_fail => fail, crypto_busy => busy,
              protected_start => ps, crypto_enable => ce, allow_access => aa,
              state_code => sc, lockdown => lock, window_valid => wv,
              blocked => blk);

  -- Generator traffic. Periode membagi WIN sehingga jumlah event per window
  -- selalu persis: NORMAL 2/window, ATTACK 10/window, PERSIST 4/window.
  gen : process
    variable cnt : natural := 0;
  begin
    wait until rising_edge(clk);
    rs <= '0'; fail <= '0';
    case mode is
      when IDLE     => cnt := 0;
      when NORMAL_M => cnt := cnt + 1;
                       if cnt >= 50 then rs <= '1'; cnt := 0; end if;
      when ATTACK_M => cnt := cnt + 1;                       -- req+fail: skor 3
                       if cnt >= 10 then rs <= '1'; fail <= '1'; cnt := 0; end if;
      when PERSIST_M => cnt := cnt + 1;                      -- skor 2, fail<FAIL_HARD
                       if cnt >= 25 then rs <= '1'; fail <= '1'; cnt := 0; end if;
    end case;
  end process;

  -- Monitor: assertion keamanan + penghitung latensi/blokir
  mon : process (clk)
  begin
    if rising_edge(clk) then
      assert not (lock = '1' and ps = '1')
        report "SECURITY VIOLATION: protected_start high during lockdown"
        severity failure;

      if not measure then
        win_cnt <= 0;
      elsif wv = '1' and lock = '0' then
        win_cnt <= win_cnt + 1;         -- window yang dievaluasi CU sebelum lock
      end if;

      if lock = '0' then
        n_req_post <= 0; n_blk_post <= 0; n_ps_post <= 0;
      else
        if rs  = '1' then n_req_post <= n_req_post + 1; end if;
        if blk = '1' then n_blk_post <= n_blk_post + 1; end if;
        if ps  = '1' then n_ps_post  <= n_ps_post  + 1; end if;
      end if;
    end if;
  end process;

  main : process
    variable k : natural;
  begin
    -- V1 reset
    rst_in <= '0'; wait for 10*T; rst_in <= '1'; wait for 5*T;
    assert sc = "00" and lock = '0' and aa = '1' report "V1 FAIL" severity error;

    -- V2 + V12: traffic normal (hanya request_start, tanpa fail/busy)
    mode <= NORMAL_M; wait for 10*WIN*T;
    assert sc = "00" and lock = '0' report "V2 FAIL: bukan NORMAL" severity error;

    -- V4: serangan berat -> LOCKDOWN
    measure <= true; mode <= ATTACK_M;
    k := 0;
    while lock = '0' and k < 20 loop wait for WIN*T; k := k + 1; end loop;
    assert lock = '1' and sc = "11" and aa = '0' and ce = '0'
      report "V4 FAIL: tidak masuk LOCKDOWN" severity error;
    report "V4: LOCKDOWN setelah " & natural'image(win_cnt) & " window";
    assert win_cnt >= 4 and win_cnt <= 5
      report "V4 FAIL: latensi di luar 4-5 window" severity error;

    -- V5: request terus dikirim setelah lockdown
    wait for 20*WIN*T;
    assert n_req_post > 0 report "V5 FAIL: tidak ada request uji" severity error;
    assert n_ps_post = 0 report "V5 FAIL: protected_start naik" severity error;
    assert n_blk_post = n_req_post report "V5 FAIL: block success < 100%" severity error;
    report "V5: request post-lock=" & natural'image(n_req_post) &
           " diblokir=" & natural'image(n_blk_post);

    -- V7: traffic berhenti, lock tetap
    mode <= IDLE; measure <= false;
    wait for 20*WIN*T;
    assert lock = '1' and sc = "11" and aa = '0'
      report "V7 FAIL: lock tidak sticky" severity error;

    -- V8: trusted physical reset
    rst_in <= '0'; wait for 5*T; rst_in <= '1'; wait for 10*T;
    assert sc = "00" and lock = '0' and aa = '1' report "V8 FAIL" severity error;

    -- V11: failure persisten di bawah FAIL_HARD -> LOCKDOWN via K_LOCK
    measure <= true; mode <= PERSIST_M;
    k := 0;
    while lock = '0' and k < 20 loop wait for WIN*T; k := k + 1; end loop;
    assert lock = '1' report "V11 FAIL: tidak masuk LOCKDOWN" severity error;
    report "V11: LOCKDOWN setelah " & natural'image(win_cnt) & " window";
    assert win_cnt >= 1 + K_SUSP + K_LK and win_cnt <= 2 + K_SUSP + K_LK
      report "V11 FAIL: latensi tidak sesuai 1+K_SUSPICIOUS+K_LOCK" severity error;

    mode <= IDLE; measure <= false;
    report "tb_top: SELESAI (cek tidak ada error/failure di atas)";
    stop <= true;
    wait;
  end process;
end architecture;
