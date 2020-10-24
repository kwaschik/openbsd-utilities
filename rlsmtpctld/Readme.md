Eine Art smtpctl "repeater" für chrooted Prozesse, die mit smtpd kommunizieren müssen.

Z.B.: rlpasswd (cgi-Programm hinter slowcgi als backend für Generic-Rest-Plugin von Rainloop)
rlpasswd verarbeitet Passwortänderungsanfragen aus Rainloop & muss am Ende smtpd diese Änderungen
irgendwie mitteilen.

rlsmtpctld öffnet ein UNIX-domain Socket, nimmt dort Befehle entgegen und ruft ggf. smtpctl auf,
um diese Befehle an smtpd weiterzugeben.
