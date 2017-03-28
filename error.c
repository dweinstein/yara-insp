#include <yara.h>

void print_error(
    int error)
{
  switch (error)
  {
    case ERROR_SUCCESS:
      break;
    case ERROR_COULD_NOT_ATTACH_TO_PROCESS:
      fprintf(stderr, "can not attach to process (try running as root)\n");
      break;
    case ERROR_INSUFICIENT_MEMORY:
      fprintf(stderr, "Insufficient memory to complete the operation\n");
      break;
    case ERROR_SCAN_TIMEOUT:
      fprintf(stderr, "scanning timed out\n");
      break;
    case ERROR_COULD_NOT_OPEN_FILE:
      fprintf(stderr, "could not open file\n");
      break;
    case ERROR_UNSUPPORTED_FILE_VERSION:
      fprintf(stderr, "rules were compiled with a newer version of YARA.\n");
      break;
    case ERROR_CORRUPT_FILE:
      fprintf(stderr, "corrupt compiled rules file.\n");
      break;
    case ERROR_EXEC_STACK_OVERFLOW:
      fprintf(stderr, "stack overflow while evaluating condition "
                      "(see --stack-size argument).\n");
      break;
    case ERROR_INVALID_FILE:
      fprintf(stderr, "File is not a valid rules file\n");
      break;
    case ERROR_INVALID_EXTERNAL_VARIABLE_TYPE:
      fprintf(stderr, "invalid type for external variable.\n");
      break;
    default:
      fprintf(stderr, "internal error: %d\n", error);
      break;
  }
}

