/**
 * @name Simple JavaScript PII Detection (Working)
 * @description Detects basic PII logging in JavaScript
 * @kind problem
 * @problem.severity warning
 * @id javascript/simple-pii-working
 */

import javascript

from VarRef ref, CallExpr call
where
  // Find variables with PII names
  (
    ref.getName().toLowerCase().matches("%email%") or
    ref.getName().toLowerCase().matches("%phone%") or
    ref.getName().toLowerCase().matches("%password%") or
    ref.getName().toLowerCase().matches("%ssn%") or
    ref.getName().toLowerCase().matches("%user%") or
    ref.getName().toLowerCase().matches("%card%")
  ) and
  // Used in logging calls
  (
    call.getCallee().(PropAccess).getPropertyName() in ["log", "info", "debug", "warn", "error"] or
    call.getCallee().(VarRef).getName() in ["log", "info", "debug", "warn", "error"]
  ) and
  // The variable is used in the call arguments
  call.getAnArgument().getAChild*() = ref
select call, "PII variable '" + ref.getName() + "' used in logging"