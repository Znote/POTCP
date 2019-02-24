# POTCP
(P)HP (O)pen (T)ibia (C)lient (P)rotocol
This is a (headless) OT client library written in PHP.

It deals with the tibia protocol, rsa/xtea encryption/decryption and communication with the server. 
Tested against [Forgottenserver 1.3](https://github.com/otland/forgottenserver). 

if you wonder why there are 2 classes, Tibia_client and Tibia_client_internal,
Tibia_client is supposed to be easy to use and easy to understand, easy to wrap your head around
while the _internal is supposed to be... the dirty complex internals :stuck_out_tongue:

## Test:
1. Modify tests/tests/loginPlayerBot.php with your servers IP, gameserver port (usually 7172), account username and password, and character name.
2. Execute tests/loginPlayerBot.php with PHP in cli. `php loginPlayerBot.php`
3. Login on another account and see the player who logged in from PHP. 
4. Ask him in-game to go in any direction, etc `go right`, `go down` and see the magic happen.
