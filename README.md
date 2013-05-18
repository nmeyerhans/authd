authd
=====

Daemon for maintaining kerberos credential freshness in a shell session

Normal usage will involve running authd in your shell init scripts. If
you log in to the host where authd is set up, it will spawn
automatically and run in the background completely detached from the
parent shell. It will periodically refresh kerberos tickets for as long
as they can be renewed. It will exit when either the parent shell exits
(e.g. you log out) or your kerberos tickets have exceded their renewable
lifetime.

