// Importing the errorHandler middleware
import { errorHandler } from "../middlewares/error.middlewares.js";

/**
 * Common Error class for throwing errors in a standardized way.
 * The errorHandler middleware will catch instances of this error centrally.
 * It helps in returning appropriate responses to the client.
 */
class ApiError extends Error {
  /**
   * Constructor for the ApiError class.
   *
   * @param {number} statusCode - HTTP status code for the error.
   * @param {string} message - Error message (default is "Something went wrong").
   * @param {any[]} errors - Array of additional error details (default is an empty array).
   * @param {string} stack - Stack trace for the error (default is an empty string).
   */
  constructor(statusCode, message = "Something went wrong", errors = [], stack = "") {
    // Call the constructor of the parent Error class with the provided message
    super(message);

    // Set properties specific to the ApiError class
    this.statusCode = statusCode; // HTTP status code
    this.data = null; // Additional data (null by default)
    this.message = message; // Error message
    this.success = false; // Indicator that the operation was not successful
    this.errors = errors; // Additional error details

    // Set the stack trace if provided, otherwise capture the stack trace
    if (stack) {
      this.stack = stack;
    } else {
      Error.captureStackTrace(this, this.constructor);
    }
  }
}

// Export the ApiError class
export { ApiError };
