# Repository guidance

## Project

- This is a GNU99 C project built with `make`.
- The main binaries are `zapret-checker`, `zapret-download`, and `rutoken-sign`.
- Core code lives in the top-level `*.c` and `*.h` files. Treat `rutoken/` as third-party PKCS#11 headers; do not edit it unless the task specifically requires it.
- `zapret-configuration.h.include` is generated from `zapret-checker.xsd`. Do not hand-edit the generated file.

## Implementation priorities

- Prefer straightforward, idiomatic C that matches the surrounding code.
- Memory and resource safety take priority over cleverness or small performance gains.
- Make ownership explicit at API boundaries. Document whether returned pointers are owned, borrowed, or transferred when the signature alone is ambiguous.
- Initialize owned pointers to `NULL` and file descriptors to `-1` so partial initialization can be cleaned up safely.
- Check every allocation and every size calculation before allocating or copying. Guard against integer overflow in `count * sizeof(...)`, additions, and protocol-derived lengths.
- Never dereference, index, or call `strlen`/`strcpy`-like operations on unvalidated external data. Validate packet, file, XML, ZIP, HTTP, and DNS lengths before access.
- Prefer length-aware operations and `size_t` for object sizes. Cast to narrower or signed types only after checking the range.
- Do not use unbounded `strcpy`, `strcat`, `sprintf`, or `scanf("%s", ...)`.
- Use `const` for read-only inputs and keep variables in the narrowest useful scope.

## Cleanup and ownership

- Follow the existing `check(...)` / `goto error` cleanup pattern where it keeps all exits correct.
- A function that acquires a resource must either release it on every exit or clearly transfer ownership to its caller.
- Keep one cleanup site for complex functions and make it safe after partial initialization.
- Pair resources with the correct release function: `free`, `xmlFree`/`xmlFreeDoc`, `curl_*_cleanup`, `curl_slist_free_all`, `curl_mime_free`, `zip_*close`/`zip_source_free`, `fclose`, `close`, `dlclose`, and library-specific destroy functions are not interchangeable.
- Handle `realloc` through a temporary pointer; never overwrite the only live pointer before success is known.
- After freeing long-lived/context members, set them to `NULL`; after closing reusable descriptors, set them to `-1`.
- Avoid double ownership. If ownership moves into a context or library object, clear the old owner or record the transfer immediately.
- Threads, child processes, sockets, and global library initialization also need balanced shutdown. Do not introduce cleanup races or free data while a worker can still access it.

## Error handling

- Check system and library return values, including short reads/writes and interrupted calls where relevant.
- Preserve enough context in errors to diagnose the failed operation without logging secrets, private-key material, passwords, signatures, or full sensitive payloads.
- Signal handlers must remain async-signal-safe; normally they should only update `volatile sig_atomic_t` flags.
- Do not silently continue with truncated, malformed, or partially initialized data.

## Validation

- Build all targets with:

  ```sh
  make
  ```

- There is currently no dedicated automated test suite. Exercise the smallest relevant binary or code path after each change.
- For memory-sensitive changes, also build and run the affected path with AddressSanitizer and UndefinedBehaviorSanitizer when the required native libraries are available:

  ```sh
  make clean
  make CFLAGS_LOCAL="-g -O1 -Wall -Wextra -std=gnu99 -fsanitize=address,undefined -fno-omit-frame-pointer $(xml2-config --cflags) $(curl-config --cflags) $(pkg-config --cflags libzip)" \
       LDFLAGS_LOCAL="-g -fsanitize=address,undefined -lnetfilter_queue $(xml2-config --libs) $(curl-config --libs) $(pkg-config --libs libzip) -ldl -lpthread -lidn2 -lm" \
       DOWNLOAD_LDFLAGS="-fsanitize=address,undefined $(xml2-config --libs) $(curl-config --libs) $(pkg-config --libs libzip) -ldl -lidn2"
  ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 ./<affected-binary> <safe-test-arguments>
  ```

- Do not claim a leak is fixed from inspection alone. Run an exercised sanitizer or Valgrind path when feasible, and report any code paths that could not be executed because they require credentials, root privileges, network access, hardware tokens, or production services.
- Before handing off, inspect the diff and ensure new warnings, unchecked allocations, ownership ambiguity, and cleanup gaps were not introduced.
