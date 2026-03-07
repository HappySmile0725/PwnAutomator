# How To Make Payload
1. 페이로드의 기본 틀은 다음과 같음.
```python
from pwn import *
p = process("./chall")
e = ELF("./chall", checksec=false)

p.interactive()
```
위 기본 틀은 pwntools mcp에서 자동으로 wrapping하여 페이로드 파일을 생성하므로 위 페이로드 생성 시 위 4줄의 코드는 적을 필요 없음.

2. 다음 규칙을 따를 것.
    - 코드는 최대한 간결하고 최소화시켜서 작성해야 함.
    - 페이로드는 Python의 pwntools를 사용하여 작성
    - `ELF()`를 통해 chall 바이너리를 가져오거나 libc 파일을 가져와야 한다면 p = process("./chall") 바로 밑에 작성. 그리고 인자값 checksec은 false로 세팅
    - p.interactive() 가 존재하므로 쉘 획득에 있어 굳이 코드로 작성하여 쉘 획득 여부까지 작성할 필요 없음