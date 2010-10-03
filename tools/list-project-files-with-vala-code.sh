grep -r ClCompile * | \
  grep IntDir | \
  grep -v "vcxproj\.filters" | \
  cut -f1 -d":" | \
  sort -u
