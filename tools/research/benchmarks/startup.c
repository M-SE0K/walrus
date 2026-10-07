/* Tigress initializes its VM arrays in main. A reactor never calls main itself.
 * Link this same constructor with both the original and transformed source so
 * Emscripten's _initialize runs main exactly once before benchmark exports.
 */
extern int main(int argc, char **argv, char **envp);

__attribute__((constructor))
static void comparison_startup(void)
{
    (void)main(0, (char **)0, (char **)0);
}
