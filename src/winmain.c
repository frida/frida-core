#include <tchar.h>
#include <windows.h>

extern int main (int argc, char ** argv);

int APIENTRY _tWinMain (HINSTANCE hInstance, HINSTANCE hPrevInstance,
    LPTSTR lpCmdLine, int nCmdShow)
{
  (void) hInstance;
  (void) hPrevInstance;
  (void) lpCmdLine;
  (void) nCmdShow;

  return main (0, NULL);
}
