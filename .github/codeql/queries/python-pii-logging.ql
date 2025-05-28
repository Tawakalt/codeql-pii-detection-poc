/**
 * @name Simple PII Logging Detection
 * @description Finds basic PII logging patterns that actually work
 * @kind problem
 * @problem.severity warning
 * @id python/simple-pii-logging
 */

import python

from Call c, Name n
where
  // Find logging calls
  (
    c.getFunc().(Attribute).getName() in ["info", "debug", "warning", "error", "critical"] or
    c.getFunc().(Name).getId() = "print"
  ) and
  // That contain variables with PII-like names
  c.getAnArg().getASubExpression*() = n and
  (
    n.getId().toLowerCase().matches("%email%") or
    n.getId().toLowerCase().matches("%phone%") or
    n.getId().toLowerCase().matches("%ssn%") or
    n.getId().toLowerCase().matches("%password%")
  )
select c, "Logging call contains PII variable: " + n.getId()