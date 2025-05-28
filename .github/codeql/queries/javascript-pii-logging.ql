/**
 * @name JavaScript PII logging detection
 * @description Detects PII in JavaScript logging
 * @kind problem
 * @problem.severity warning
 * @id javascript/pii-logging
 */

import javascript

from CallExpr call, Expr arg
where
  (
    call.getCalleeName() = "log" or
    call.getCalleeName() = "info" or
    call.getCalleeName() = "debug" or
    call.getCalleeName() = "warn" or
    call.getCalleeName() = "error"
  ) and
  call.getAnArgument() = arg and
  (
    arg.(VarRef).getName().toLowerCase().matches("%email%") or
    arg.(VarRef).getName().toLowerCase().matches("%phone%") or
    arg.(VarRef).getName().toLowerCase().matches("%password%")
  )
select call, "Potential PII logging in JavaScript"