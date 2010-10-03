#!/usr/bin/env python

import os
import sys

for project_file in sys.stdin:
    project_file = project_file.strip()
    with open(project_file, 'rb') as f:
        buf = f.read()

    result = ''
    offset = 0

    while True:
        next_start = buf.find('<ClCompile Include=', offset)
        if next_start < 0:
            result += buf[offset:]
            break
        result += buf[offset:next_start]

        body_start = buf.find('>', next_start + 10)
        assert body_start >= 0

        tag = buf[next_start:body_start + 1]

        if buf[body_start - 1] == '/':
            body_end = body_start
            next_end = body_start + 1
        else:
            body_start += 1

            body_end = buf.find('</ClCompile>', body_start)
            assert body_end >= 0

            next_end = body_end + 12

        if 'IntDir' in tag:
            if tag.endswith ('/>'):
                tag = tag[:-2] + '>'
                if tag.endswith (' >'):
                    tag = tag[:-2] + '>'
            blob = buf[next_start:next_end]

            start = buf.find('$(IntDir)', next_start)
            assert start >= 0
            start += 9
            end = buf.find('"', start)
            assert end >= 0
            filename = buf[start:end]
            assert not '..' in filename

            lines = \
            [
                """<WarningLevel Condition="'$(Configuration)|$(Platform)'=='Debug|Win32'">TurnOffAllWarnings</WarningLevel>""",
                """<WarningLevel Condition="'$(Configuration)|$(Platform)'=='Release|Win32'">TurnOffAllWarnings</WarningLevel>""",
                """<WarningLevel Condition="'$(Configuration)|$(Platform)'=='Debug|x64'">TurnOffAllWarnings</WarningLevel>""",
                """<WarningLevel Condition="'$(Configuration)|$(Platform)'=='Release|x64'">TurnOffAllWarnings</WarningLevel>"""
            ]

            subdir = os.path.dirname(filename)
            if subdir:
                lines.extend (\
                    [
                        """<ObjectFileName Condition="'$(Configuration)|$(Platform)'=='Debug|Win32'">$(IntDir)%s\</ObjectFileName>""" % subdir,
                        """<ObjectFileName Condition="'$(Configuration)|$(Platform)'=='Release|Win32'">$(IntDir)%s\</ObjectFileName>""" % subdir,
                        """<ObjectFileName Condition="'$(Configuration)|$(Platform)'=='Debug|x64'">$(IntDir)%s\</ObjectFileName>""" % subdir,
                        """<ObjectFileName Condition="'$(Configuration)|$(Platform)'=='Release|x64'">$(IntDir)%s\</ObjectFileName>""" % subdir,
                    ]
                )

            if '>true</ExcludedFromBuild>' in blob:
                lines.extend (\
                    [
                        """<ExcludedFromBuild Condition="'$(Configuration)|$(Platform)'=='Debug|Win32'">true</ExcludedFromBuild>""",
                        """<ExcludedFromBuild Condition="'$(Configuration)|$(Platform)'=='Debug|x64'">true</ExcludedFromBuild>""",
                        """<ExcludedFromBuild Condition="'$(Configuration)|$(Platform)'=='Release|Win32'">true</ExcludedFromBuild>""",
                        """<ExcludedFromBuild Condition="'$(Configuration)|$(Platform)'=='Release|x64'">true</ExcludedFromBuild>""",
                    ]
                )

            indent = '  '
            blob = tag + '\n' + (indent * 3) + ('\n' + (indent * 3)).join (lines) + '\n' + (indent * 2) + '</ClCompile>'
        else:
            blob = buf[next_start:next_end]

        result += blob
        offset = next_end

    result = result.replace('\r', '').replace('\n', '\r\n')
    with open(project_file, 'wb') as f:
        f.write(result)

