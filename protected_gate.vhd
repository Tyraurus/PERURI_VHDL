--------------------------------------------------------------------------------
-- protected_gate.vhd
-- Gate enforcement eksplisit (R6). Murni kombinasional: tidak ada register,
-- tidak ada bypass. protected_start hanya dapat '1' jika allow_access = '1'.
--------------------------------------------------------------------------------
library ieee;
use ieee.std_logic_1164.all;

entity protected_gate is
  port (
    request_start   : in  std_logic;  -- dari untrusted domain
    allow_access    : in  std_logic;  -- dari security_cu (hardwired)
    protected_start : out std_logic;  -- ke protected resource
    blocked         : out std_logic   -- observasi: request ditolak gate
  );
end entity;

architecture rtl of protected_gate is
begin
  protected_start <= request_start and allow_access;
  blocked         <= request_start and (not allow_access);
end architecture;
