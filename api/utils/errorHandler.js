export const errorHandler = (statusCode, errMessage) => {
  const error = new Error();
  error.statusCode = statusCode;
  error.errorMessage = errMessage;
  return error;
};
