/**
 * @name Simple PII Detection (Working)
 * @description Detects basic PII logging patterns that actually work
 * @kind problem
 * @problem.severity warning
 * @id python/simple-pii-working
 */

import python

from Name n, Call c
where 
  // Find variables with PII-like names
  (
    n.getId().toLowerCase().matches("%email%") or
    n.getId().toLowerCase().matches("%phone%") or
    n.getId().toLowerCase().matches("%password%") or
    n.getId().toLowerCase().matches("%ssn%") or
    n.getId().toLowerCase().matches("%address%")
  ) and
  // That are used in logging calls
  (
    c.getFunc().(Attribute).getName() in ["info", "debug", "warning", "error"] or
    c.getFunc().(Name).getId() = "print"
  ) and
  // The variable is an argument to the logging call
  c.getAnArg().getASubExpression*() = n
select c, "PII variable '" + n.getId() + "' used in logging call"