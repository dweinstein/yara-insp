#include <yara.h>

#include "args.h"
#include "config.h"
#include "error.h"

#define MAX_ARGS_TAG    32

int show_version = FALSE;
int show_help = FALSE;
int show_tags = FALSE;

#define USAGE_STRING \
    "Usage: ytags [OPTION]... RULES_FILE"

args_option_t options[] =
{
  OPT_BOOLEAN('v', "version", &show_version,
      "show version information"),

  OPT_BOOLEAN('h', "help", &show_help,
      "show this help and exit"),

  OPT_END()
};

#define exit_with_code(code) { result = code; goto _exit; }

int main(int argc, const char** argv) {
  YR_RULES* rules = NULL;
  YR_RULE* cur_rule = NULL;
  YR_META* meta = NULL;

  const char* tag;

  argc = args_parse(options, argc, argv);

  int result;
  if (show_version)
  {
    printf("%s\n", PACKAGE_STRING);
    return EXIT_SUCCESS;
  }

  if (show_help)
  {
    printf(
        "YARA %s, the pattern matching swiss army knife.\n"
        "%s\n\n"
        "Mandatory arguments to long options are mandatory for "
        "short options too.\n\n", PACKAGE_VERSION, USAGE_STRING);

    args_print_usage(options, 35);
    printf("\nSend bug reports and suggestions to: %s.\n", PACKAGE_BUGREPORT);

    return EXIT_SUCCESS;
  }

  if (argc != 1)
  {
    // After parsing the command-line options we expect two additional
    // arguments, the rules file and the target file, directory or pid to
    // be scanned.

    fprintf(stderr, "yara: wrong number of arguments\n");
    fprintf(stderr, "%s\n\n", USAGE_STRING);
    fprintf(stderr, "Try `--help` for more options\n");

    return EXIT_FAILURE;
  }

  result = yr_initialize();

  if (result != ERROR_SUCCESS)
  {
    fprintf(stderr, "error: initialization error (%d)\n", result);
    exit_with_code(EXIT_FAILURE);
  }

  result = yr_rules_load(argv[0], &rules);

  // Accepted result are ERROR_SUCCESS or ERROR_INVALID_FILE
  // if we are passing the rules in source form, if result is
  // different from those exit with error.

  if (result != ERROR_SUCCESS &&
      result != ERROR_INVALID_FILE)
  {
    print_error(result);
    exit_with_code(EXIT_FAILURE);
  }

  if (result == ERROR_SUCCESS)
  {
    yr_rules_foreach(rules, cur_rule)
    {
      printf("rule %s :", cur_rule->identifier);
      yr_rule_tags_foreach(cur_rule, tag)
      {
        printf(" %s", tag);
      }
      printf("\n");
    }
  } else {
    print_error(result);
    exit_with_code(EXIT_FAILURE);
  }

_exit:
  if (rules != NULL)
    yr_rules_destroy(rules);
  return result;
}
