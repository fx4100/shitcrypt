# shitcrypt
a random enc/dec tool that looks "secure" but NOT FUCKING IS.
it *looks* secure.
it *feels* secure.
but nah, CIA will catch your ass.
if you want **that** secure,
get the fuck out and find real libraries.

### then what is this?
random shit, experimental CPU load test.
useful for overclock stability test, tho.
used it for my FX-4100 and it crashed thanks to undervoltage.

### why?
as i said, **experimental**. use it for either stability tests or "ooh, i wanna see how it encrypts!"
**fun**.

### usage
it could either encrypt or decrypt a text or file by given pass, read the .py or "shit.py --h" for more details.

what it does is simple:
u give pass and text/file, gets stretched using repeated SHA-256 (shit KDF), splits input into 32-bit words, continous rounds with XOR shit, parallellizes with `ProcessPoolExecutor` and succesfully fucks CPU, final output is hex-coded with a header so the rounds can be found and used easily to decrypt. do NOT use for private or real shit.

### license
MIT.
do whatever u want.
***im not responsible for illegal usage nor thermonuclear war.***
