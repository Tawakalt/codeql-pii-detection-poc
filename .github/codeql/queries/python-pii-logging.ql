/**
 * @name Enhanced PII logging detection with structlog support (Python)
 * @description Detects when personally identifiable information may be logged including structlog patterns
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id python/enhanced-pii-logging-structlog
 * @tags security
 *       privacy
 *       external/cwe/cwe-532
 *       external/owasp/owasp-a09-2021
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

/**
 * A data flow source of sensitive PII data
 */
class SensitiveDataSource extends DataFlow::Node {
  SensitiveDataSource() {
    // Variable names containing PII keywords
    exists(Name n | 
      this.asExpr() = n and
      (
        // Email patterns
        n.getId().toLowerCase().matches("%email%") or
        n.getId().toLowerCase().matches("%e_mail%") or
        n.getId().toLowerCase().matches("%mail%") or
        // Phone patterns
        n.getId().toLowerCase().matches("%phone%") or
        n.getId().toLowerCase().matches("%mobile%") or
        n.getId().toLowerCase().matches("%tel%") or
        // SSN and ID patterns
        n.getId().toLowerCase().matches("%ssn%") or
        n.getId().toLowerCase().matches("%social%security%") or
        n.getId().toLowerCase().matches("%tax%id%") or
        // Credit card patterns
        n.getId().toLowerCase().matches("%credit%") or
        n.getId().toLowerCase().matches("%card%number%") or
        n.getId().toLowerCase().matches("%cvv%") or
        n.getId().toLowerCase().matches("%cvc%") or
        // Password patterns
        n.getId().toLowerCase().matches("%password%") or
        n.getId().toLowerCase().matches("%passwd%") or
        n.getId().toLowerCase().matches("%pwd%") or
        // Address patterns
        n.getId().toLowerCase().matches("%address%") or
        n.getId().toLowerCase().matches("%street%") or
        n.getId().toLowerCase().matches("%zip%") or
        n.getId().toLowerCase().matches("%postal%") or
        // Name patterns
        n.getId().toLowerCase().matches("%first%name%") or
        n.getId().toLowerCase().matches("%last%name%") or
        n.getId().toLowerCase().matches("%full%name%") or
        n.getId().toLowerCase().matches("%surname%") or
        // Personal info patterns
        n.getId().toLowerCase().matches("%personal%") or
        n.getId().toLowerCase().matches("%private%") or
        n.getId().toLowerCase().matches("%sensitive%") or
        // User data patterns
        n.getId().toLowerCase().matches("%user%data%") or
        n.getId().toLowerCase().matches("%profile%data%") or
        n.getId().toLowerCase().matches("%customer%info%") or
        // Medical patterns
        n.getId().toLowerCase().matches("%medical%") or
        n.getId().toLowerCase().matches("%health%") or
        n.getId().toLowerCase().matches("%patient%")
      )
    )
    or
    // Dictionary/subscript access with PII keys
    exists(Subscript s |
      this.asExpr() = s and
      exists(StrConst key |
        s.getIndex() = key and
        (
          key.getText().toLowerCase().matches("%email%") or
          key.getText().toLowerCase().matches("%phone%") or
          key.getText().toLowerCase().matches("%ssn%") or
          key.getText().toLowerCase().matches("%password%") or
          key.getText().toLowerCase().matches("%address%") or
          key.getText().toLowerCase().matches("%first_name%") or
          key.getText().toLowerCase().matches("%last_name%") or
          key.getText().toLowerCase().matches("%credit_card%") or
          key.getText().toLowerCase().matches("%card_number%") or
          key.getText().toLowerCase().matches("%cvv%") or
          key.getText().toLowerCase().matches("%personal%") or
          key.getText().toLowerCase().matches("%sensitive%") or
          key.getText().toLowerCase().matches("%private%")
        )
      )
    )
    or
    // Function calls that likely return sensitive data
    exists(Call c |
      this.asExpr() = c and
      (
        c.getFunc().(Name).getId().toLowerCase().matches("%get%user%") or
        c.getFunc().(Name).getId().toLowerCase().matches("%fetch%user%") or
        c.getFunc().(Name).getId().toLowerCase().matches("%load%user%") or
        c.getFunc().(Name).getId().toLowerCase().matches("%personal%info%") or
        c.getFunc().(Name).getId().toLowerCase().matches("%sensitive%data%") or
        c.getFunc().(Name).getId().toLowerCase().matches("%user%details%") or
        c.getFunc().(Name).getId().toLowerCase().matches("%get%profile%") or
        c.getFunc().(Name).getId().toLowerCase().matches("%customer%data%") or
        c.getFunc().(Attribute).getName().toLowerCase().matches("%get%user%") or
        c.getFunc().(Attribute).getName().toLowerCase().matches("%personal%info%")
      )
    )
    or
    // Attribute access on user/profile objects
    exists(Attribute attr |
      this.asExpr() = attr and
      (
        attr.getName() in [
          "email", "phone", "ssn", "password", "address", 
          "first_name", "last_name", "full_name", "credit_card",
          "card_number", "cvv", "personal_info", "sensitive_data"
        ] or
        attr.getName().toLowerCase().matches("%email%") or
        attr.getName().toLowerCase().matches("%phone%") or
        attr.getName().toLowerCase().matches("%personal%")
      )
    )
  }
}

/**
 * A data flow sink representing logging operations
 */
class LoggingSink extends DataFlow::Node {
  LoggingSink() {
    // Standard logging method calls
    exists(Call c |
      this.asExpr() = c.getAnArg() and
      (
        // Standard logger methods
        c.getFunc().(Attribute).getName() in [
          "debug", "info", "warning", "warn", "error", "exception", "critical", "log"
        ] or
        // Print statements
        c.getFunc().(Name).getId() = "print" or
        // Console methods (for JavaScript-style logging in Python)
        c.getFunc().(Attribute).getName() in ["log", "warn", "error"]
      )
    )
    or
    // Structlog keyword arguments with PII parameter names
    exists(Call c, Keyword kw |
      c.getAKeyword() = kw and
      this.asExpr() = kw.getValue() and
      (
        // Direct PII parameter names
        kw.getArg().toLowerCase().matches("%email%") or
        kw.getArg().toLowerCase().matches("%phone%") or
        kw.getArg().toLowerCase().matches("%ssn%") or
        kw.getArg().toLowerCase().matches("%password%") or
        kw.getArg().toLowerCase().matches("%address%") or
        kw.getArg().toLowerCase().matches("%first%name%") or
        kw.getArg().toLowerCase().matches("%last%name%") or
        kw.getArg().toLowerCase().matches("%full%name%") or
        kw.getArg().toLowerCase().matches("%personal%") or
        kw.getArg().toLowerCase().matches("%user%data%") or
        kw.getArg().toLowerCase().matches("%profile%") or
        kw.getArg().toLowerCase().matches("%customer%") or
        kw.getArg().toLowerCase().matches("%card%") or
        kw.getArg().toLowerCase().matches("%cvv%") or
        kw.getArg().toLowerCase().matches("%credit%") or
        kw.getArg().toLowerCase().matches("%holder%name%") or
        kw.getArg().toLowerCase().matches("%sensitive%") or
        kw.getArg().toLowerCase().matches("%private%")
      ) and
      (
        // Structlog method calls
        c.getFunc().(Attribute).getName() in [
          "debug", "info", "warning", "warn", "error", "exception", "critical"
        ]
      )
    )
    or
    // Structlog bind method calls (context binding with PII)
    exists(Call bind_call, Keyword kw |
      bind_call.getFunc().(Attribute).getName() = "bind" and
      bind_call.getAKeyword() = kw and
      this.asExpr() = kw.getValue() and
      (
        kw.getArg().toLowerCase().matches("%email%") or
        kw.getArg().toLowerCase().matches("%phone%") or
        kw.getArg().toLowerCase().matches("%user%") or
        kw.getArg().toLowerCase().matches("%personal%") or
        kw.getArg().toLowerCase().matches("%customer%") or
        kw.getArg().toLowerCase().matches("%profile%") or
        kw.getArg().toLowerCase().matches("%sensitive%") or
        kw.getArg().toLowerCase().matches("%card%") or
        kw.getArg().toLowerCase().matches("%address%") or
        kw.getArg().toLowerCase().matches("%ssn%") or
        kw.getArg().toLowerCase().matches("%password%")
      )
    )
    or
    // String formatting in log messages (f-strings, .format(), % formatting)
    exists(Call c |
      this.asExpr() = c.getAnArg() and
      c.getFunc().(Attribute).getName() in [
        "debug", "info", "warning", "warn", "error", "exception", "critical", "log"
      ] and
      (
        // F-string expressions
        exists(FormattedValue fv |
          c.getAnArg().(JoinedStr).getAValue() = fv and
          this.asExpr() = fv.getValue()
        ) or
        // .format() method calls
        exists(Call format_call |
          c.getAnArg() = format_call and
          format_call.getFunc().(Attribute).getName() = "format" and
          this.asExpr() = format_call.getAnArg()
        )
      )
    )
  }
}

/**
 * Taint tracking configuration for PII logging detection
 */
class PiiLoggingConfig extends TaintTracking::Configuration {
  PiiLoggingConfig() { this = "PiiLoggingConfig" }
  
  override predicate isSource(DataFlow::Node source) {
    source instanceof SensitiveDataSource
  }
  
  override predicate isSink(DataFlow::Node sink) {
    sink instanceof LoggingSink
  }
  
  override predicate isSanitizer(DataFlow::Node node) {
    // Functions that hash, mask, or anonymize data
    exists(Call c |
      node.asExpr() = c and
      (
        // Hash functions
        c.getFunc().(Name).getId() in ["hash", "sha256", "md5", "blake2b"] or
        c.getFunc().(Attribute).getName() in ["hash", "hexdigest", "digest"] or
        c.getFunc().(Attribute).getObject().(Name).getId() = "hashlib" or
        // Masking/anonymization functions
        c.getFunc().(Name).getId().toLowerCase().matches("%mask%") or
        c.getFunc().(Name).getId().toLowerCase().matches("%anonymize%") or
        c.getFunc().(Name).getId().toLowerCase().matches("%redact%") or
        c.getFunc().(Name).getId().toLowerCase().matches("%sanitize%") or
        c.getFunc().(Attribute).getName().toLowerCase().matches("%mask%") or
        c.getFunc().(Attribute).getName().toLowerCase().matches("%anonymize%") or
        // Encoding functions that might be used for obfuscation
        c.getFunc().(Attribute).getName() in ["encode", "b64encode"] or
        // Custom PII-safe functions (add your own patterns here)
        c.getFunc().(Name).getId().toLowerCase().matches("%hash%pii%") or
        c.getFunc().(Name).getId().toLowerCase().matches("%safe%log%") or
        c.getFunc().(Name).getId().toLowerCase().matches("%secure%format%")
      )
    )
    or
    // String slicing that might mask data (e.g., email[:3] + "***")
    exists(Subscript s |
      node.asExpr() = s and
      exists(Slice slice | s.getIndex() = slice)
    )
  }
  
  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    // Dictionary unpacking (**dict) passes taint
    exists(Dict d, DictUnpacking du |
      node1.asExpr() = d and
      node2.asExpr() = du and
      du.getMapping() = d
    )
    or
    // Method chaining in structlog (bind returns logger that can be called)
    exists(Call bind_call, Call log_call |
      bind_call.getFunc().(Attribute).getName() = "bind" and
      node1.asExpr() = bind_call and
      log_call.getFunc().(Attribute).getObject() = bind_call and
      node2.asExpr() = log_call
    )
  }
}

from PiiLoggingConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Potential PII logging: sensitive data from $@ may be logged here. " +
  "Consider using user IDs, hashing, or masking instead of logging PII directly.", 
  source.getNode(), "this source"