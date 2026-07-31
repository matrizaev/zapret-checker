#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dbg.h"
#include "sign.h"

static int hex_value(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

static int decode_key_id(const char *hex, uint8_t *output,
                         size_t *output_length) {
  size_t input_length = strlen(hex);
  if (input_length == 0 || input_length % 2 != 0)
    return -1;
  for (size_t i = 0; i < input_length; i += 2) {
    int high = hex_value(hex[i]);
    int low = hex_value(hex[i + 1]);
    if (high < 0 || low < 0)
      return -1;
    output[i / 2] = (uint8_t)((high << 4) | low);
  }
  *output_length = input_length / 2;
  return 0;
}

int main(int argc, char *argv[]) {

  FILE *input_file = NULL;
  FILE *signature_file = NULL;
  char *signature_name = NULL;
  uint8_t *key_pair_id = NULL;
  uint8_t *buffer = NULL;
  uint8_t *signature = NULL;
  int exit_code = EXIT_FAILURE;

  check(argc == 5,
        "Usage: rutoken-sign <file> <user_pin> <key_pair_id> <slot>");

  char *file_name = argv[1];
  char *user_pin = argv[2];
  char *key_pair_id_hex = argv[3];
  int slot = atoi(argv[4]);
  size_t key_pair_id_length = 0;

  key_pair_id = calloc(strlen(key_pair_id_hex) / 2 + 1, sizeof(uint8_t));
  check_mem(key_pair_id);
  check(decode_key_id(key_pair_id_hex, key_pair_id, &key_pair_id_length) == 0,
        "key_pair_id must contain an even number of hexadecimal digits");

  input_file = fopen(file_name, "rb");
  check(input_file, "Could not open file %s", file_name);

  /* Five characters for ".sign", plus one for the terminating null byte. */
  size_t signature_name_size = strlen(file_name) + strlen(".sign") + 1;
  signature_name = calloc(signature_name_size, sizeof(char));
  check_mem(signature_name);
  check(snprintf(signature_name, signature_name_size, "%s.sign", file_name) ==
            (int)signature_name_size - 1,
        "Could not compose the signature file name");

  check(fseek(input_file, 0, SEEK_END) != -1,
        "Could not seek inside the input file");
  long input_file_offset = ftell(input_file);
  check(input_file_offset >= 0 && (uintmax_t)input_file_offset <= SIZE_MAX,
        "Could not determine the input file size");
  size_t input_file_size = (size_t)input_file_offset;
  check(fseek(input_file, 0, SEEK_SET) != -1,
        "Could not seek inside the input file");

  buffer = calloc(input_file_size == 0 ? 1 : input_file_size, sizeof(uint8_t));
  check_mem(buffer);

  check(fread(buffer, 1, input_file_size, input_file) == input_file_size,
        "Could not read the input file");

  size_t signature_size = 0;
  signature =
      SigningPerform(buffer, input_file_size, &signature_size,
                     (uint8_t *)user_pin,
                     strlen(user_pin), key_pair_id, key_pair_id_length, slot);
  check(signature != NULL, "Could not sign the input file");
  check(signature_size > 0, "Could not sign the input file");

  signature_file = fopen(signature_name, "wb");
  check(signature_file, "Could not open the signature file %s", signature_name);
  check(fwrite(signature, 1, signature_size, signature_file) == signature_size,
        "Could not write the signature to the file");
  exit_code = EXIT_SUCCESS;

error:
  if (input_file)
    fclose(input_file);
  if (signature_name)
    free(signature_name);
  if (key_pair_id)
    free(key_pair_id);
  if (buffer)
    free(buffer);
  if (signature)
    free(signature);
  if (signature_file)
    fclose(signature_file);
  return exit_code;
}
