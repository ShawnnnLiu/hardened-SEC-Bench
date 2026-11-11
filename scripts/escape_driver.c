/* Unit driver for the SVG escape routines of LibreDWG (programs/escape.c).
 *
 * Usage: escape_driver a|w|A|W [HEX]
 *   a  htmlescape (src, 0) on the bytes given as HEX (two digits per byte)
 *   w  htmlwescape (wstr) on the UTF-16 code units given as HEX (four
 *      digits per unit, most significant digit first)
 *   A  htmlescape (NULL, 0)
 *   W  htmlwescape (NULL)
 * The input is copied into a heap block of exactly its length plus the
 * terminator, so that a read past the input is visible to AddressSanitizer.
 * Prints "NULL" or the result as hex (two digits per byte), then a newline.
 *
 * Built by scripts/escape_cases.py with the compiler and flags of the
 * tree's programs/Makefile, linked with the tree's programs/escape.c.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "escape.h"

static int
hexval (int c)
{
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

static void
print_result (const char *r)
{
  const unsigned char *p;
  if (!r)
    {
      printf ("NULL\n");
      return;
    }
  for (p = (const unsigned char *)r; *p; p++)
    printf ("%02x", *p);
  printf ("\n");
}

int
main (int argc, char *argv[])
{
  const char *hex = argc > 2 ? argv[2] : "";
  size_t hlen = strlen (hex), i;
  char *r;

  if (argc < 2)
    {
      fprintf (stderr, "usage: escape_driver a|w|A|W [HEX]\n");
      return 2;
    }
  switch (argv[1][0])
    {
    case 'A':
      r = htmlescape (NULL, 0);
      break;
    case 'W':
      r = htmlwescape (NULL);
      break;
    case 'a':
      {
        size_t n = hlen / 2;
        char *s = malloc (n + 1);
        for (i = 0; i < n; i++)
          s[i] = (char)(hexval (hex[2 * i]) << 4 | hexval (hex[2 * i + 1]));
        s[n] = 0;
        r = htmlescape (s, 0);
        free (s);
        break;
      }
    case 'w':
      {
        size_t n = hlen / 4;
        BITCODE_TU s = malloc ((n + 1) * sizeof (*s));
        for (i = 0; i < n; i++)
          s[i] = (hexval (hex[4 * i]) << 12) | (hexval (hex[4 * i + 1]) << 8)
                 | (hexval (hex[4 * i + 2]) << 4) | hexval (hex[4 * i + 3]);
        s[n] = 0;
        r = htmlwescape (s);
        free (s);
        break;
      }
    default:
      fprintf (stderr, "unknown mode %s\n", argv[1]);
      return 2;
    }
  print_result (r);
  free (r);
  return 0;
}
