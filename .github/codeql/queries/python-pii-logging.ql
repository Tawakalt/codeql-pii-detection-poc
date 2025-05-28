/**
 * @name Find All Variables
 * @description Finds every single variable in Python code
 * @kind problem
 * @problem.severity warning
 * @id python/find-all-vars
 */

import python

from Name n
select n, "Found variable: " + n.getId()