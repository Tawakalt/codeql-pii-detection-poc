/**
 * @name JavaScript PII logging detection
 * @description Detects when personally identifiable information may be logged in JavaScript
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id javascript/pii-logging-detection
 * @tags security
 *       privacy
 *       external/cwe/cwe-532
 */

import javascript
import semmle.javascript.dataflow.DataFlow

/**
 * A data flow source of sensitive PII data in JavaScript
 */
abstract class SensitiveDataSource extends DataFlow::Node { }

/**
 * Variable references with PII-like names
 */
class PiiVariableSource extends SensitiveDataSource {
  PiiVariableSource() {
    exists(VarRef ref |
      this = DataFlow::valueNode(ref) and
      (
        // Email patterns
        ref.getName().toLowerCase().matches("%email%") or
        ref.getName().toLowerCase().matches("%mail%") or
        // Phone patterns  
        ref.getName().toLowerCase().matches("%phone%") or
        ref.getName().toLowerCase().matches("%mobile%") or
        ref.getName().toLowerCase().matches("%tel%") or
        // SSN and ID patterns
        ref.getName().toLowerCase().matches("%ssn%") or
        ref.getName().toLowerCase().matches("%social%security%") or
        ref.getName().toLowerCase().matches("%tax%id%") or
        // Credit card patterns
        ref.getName().toLowerCase().matches("%credit%") or
        ref.getName().toLowerCase().matches("%card%number%") or
        ref.getName().toLowerCase().matches("%cvv%") or
        ref.getName().toLowerCase().matches("%cvc%") or
        // Password patterns
        ref.getName().toLowerCase().matches("%password%") or
        ref.getName().toLowerCase().matches("%passwd%") or
        ref.getName().toLowerCase().matches("%pwd%") or
        // Address patterns
        ref.getName().toLowerCase().matches("%address%") or
        ref.getName().toLowerCase().matches("%street%") or
        ref.getName().toLowerCase().matches("%zip%") or
        ref.getName().toLowerCase().matches("%postal%") or
        // Name patterns
        ref.getName().toLowerCase().matches("%first%name%") or
        ref.getName().toLowerCase().matches("%last%name%") or
        ref.getName().toLowerCase().matches("%full%name%") or
        ref.getName().toLowerCase().matches("%surname%") or
        // Personal info patterns
        ref.getName().toLowerCase().matches("%personal%") or
        ref.getName().toLowerCase().matches("%private%") or
        ref.getName().toLowerCase().matches("%sensitive%") or
        // User data patterns
        ref.getName().toLowerCase().matches("%user%data%") or
        ref.getName().toLowerCase().matches("%profile%data%") or
        ref.getName().toLowerCase().matches("%customer%info%")
      )
    )
  }
}

/**
 * Property access with PII-like property names
 */
class PiiPropertySource extends SensitiveDataSource {
  PiiPropertySource() {
    exists(PropAccess prop |
      this = DataFlow::valueNode(prop) and
      (
        prop.getPropertyName().toLowerCase().matches("%email%") or
        prop.getPropertyName().toLowerCase().matches("%phone%") or
        prop.getPropertyName().toLowerCase().matches("%password%") or
        prop.getPropertyName().toLowerCase().matches("%ssn%") or
        prop.getPropertyName().toLowerCase().matches("%address%") or
        prop.getPropertyName().toLowerCase().matches("%first_name%") or
        prop.getPropertyName().toLowerCase().matches("%last_name%") or
        prop.getPropertyName().toLowerCase().matches("%credit_card%") or
        prop.getPropertyName().toLowerCase().matches("%card_number%") or
        prop.getPropertyName().toLowerCase().matches("%cvv%") or
        prop.getPropertyName().toLowerCase().matches("%personal%") or
        prop.getPropertyName().toLowerCase().matches("%sensitive%")
      )
    )
  }
}

/**
 * Bracket notation access with PII keys
 */
class PiiBracketSource extends SensitiveDataSource {
  PiiBracketSource() {
    exists(PropAccess prop, StringLiteral key |
      this = DataFlow::valueNode(prop) and
      prop.getProperty() = key and
      (
        key.getValue().toLowerCase().matches("%email%") or
        key.getValue().toLowerCase().matches("%phone%") or
        key.getValue().toLowerCase().matches("%password%") or
        key.getValue().toLowerCase().matches("%ssn%") or
        key.getValue().toLowerCase().matches("%address%") or
        key.getValue().toLowerCase().matches("%personal%")
      )
    )
  }
}

/**
 * A data flow sink representing logging operations in JavaScript
 */
abstract class LoggingSink extends DataFlow::Node { }

/**
 * Console logging methods
 */
class ConsoleLoggingSink extends LoggingSink {
  ConsoleLoggingSink() {
    exists(MethodCallExpr call |
      this = DataFlow::valueNode(call.getAnArgument()) and
      call.getReceiver().(VarRef).getName() = "console" and
      call.getMethodName() in ["log", "info", "debug", "warn", "error", "trace"]
    )
  }
}

/**
 * Winston/other logger method calls
 */
class LoggerSink extends LoggingSink {
  LoggerSink() {
    exists(MethodCallExpr call |
      this = DataFlow::valueNode(call.getAnArgument()) and
      call.getMethodName() in ["log", "info", "debug", "warn", "error", "verbose", "silly"]
    )
  }
}

/**
 * Template literal expressions in logging calls
 */
class TemplateLiteralSink extends LoggingSink {
  TemplateLiteralSink() {
    exists(CallExpr call, TemplateLiteral template, TemplateElement elem |
      call.getAnArgument() = template and
      template.getAnElement() = elem and
      elem instanceof TemplateElement and
      this = DataFlow::valueNode(elem.getValue()) and
      (
        call.getCallee().(PropAccess).getPropertyName() in ["log", "info", "debug", "warn", "error"] or
        call.getCallee().(VarRef).getName() in ["log", "info", "debug", "warn", "error"]
      )
    )
  }
}

/**
 * String concatenation in logging
 */
class StringConcatSink extends LoggingSink {
  StringConcatSink() {
    exists(CallExpr call, AddExpr concat |
      call.getAnArgument() = concat and
      this = DataFlow::valueNode(concat.getAnOperand()) and
      (
        call.getCallee().(PropAccess).getPropertyName() in ["log", "info", "debug", "warn", "error"] or
        call.getCallee().(VarRef).getName() in ["log", "info", "debug", "warn", "error"]
      )
    )
  }
}

/**
 * Data flow configuration for PII logging detection
 */
class PiiLoggingConfiguration extends DataFlow::Configuration {
  PiiLoggingConfiguration() { this = "PiiLoggingConfiguration" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof SensitiveDataSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof LoggingSink
  }

  override predicate isBarrier(DataFlow::Node barrier) {
    // Functions that sanitize/mask data
    exists(CallExpr call |
      barrier = DataFlow::valueNode(call) and
      (
        call.getCalleeName().toLowerCase().matches("%hash%") or
        call.getCalleeName().toLowerCase().matches("%mask%") or
        call.getCalleeName().toLowerCase().matches("%anonymize%") or
        call.getCalleeName().toLowerCase().matches("%redact%") or
        call.getCalleeName().toLowerCase().matches("%sanitize%")
      )
    )
  }
}

from PiiLoggingConfiguration config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Potential PII logging: sensitive data from $@ may be logged here. " +
  "Consider using user IDs, hashing, or masking instead of logging PII directly.",
  source.getNode(), "this source"