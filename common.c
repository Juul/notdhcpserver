
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>


int run_hook_script(char* hook_script_path, ...) {
  va_list args;
  char* cur;
  char* cmd;
  int len;
  int i;
  int ret;

  if(!hook_script_path) {
    return;
  }

  len = strlen(hook_script_path + 1);
  
  va_start(args, hook_script_path); 
  
  while((cur = va_arg(args, char *)) != NULL) {
    len += strlen(cur) + 1;
  }
  
  va_end(args);

  cmd = malloc(len);

  va_start(args, hook_script_path); 
  
  i = 0;
  strcpy(cmd, hook_script_path);
  i += strlen(hook_script_path);
  cmd[i++] = ' ';

  while((cur = va_arg(args, char *)) != NULL) {
    strcpy(cmd + i, cur);
    i += strlen(cur);
    cmd[i++] = ' ';
  }

  cmd[i-1] = '\0';
    
  va_end(args);

  ret = system(cmd);

  free(cmd);

  return ret;
}
