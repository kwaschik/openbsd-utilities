/* CGI-Programm als Service für die Passwortänderung in
 * Rainloop mit dem Generic_Rest_Plugin.
 * Gedacht, um hinter OpenBSD httpd/slowcgi zu laufen.
 */

#include <netinet/in.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <pwd.h>
#include <resolv.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* from httpd.c */
char 	*url_decode(char *);

int
main(int argc, char **argv, char **envp)
{
	FILE	   *passwdFile;
	char	   *input, *_pInput, *decoded, *_pDecoded, *passwdLine;
	const char *errstr;
	char	    hash[_PASSWORD_LEN];
	char 	   *contLen, *contType; 
	char	   *item, *key, *email, *newpw, *oldpw, *user;
	size_t	    contSize, passwdLineSize;
	ssize_t	    passwdLineLen;

	_pInput    	= _pDecoded = passwdLine = user = NULL;
	passwdFile     	= NULL;
	passwdLineSize 	= 0;


	/* CGI: Viele Infos werden mittels Umgebungsvariablen übergeben.
	 * Ohne Umgebung geht's daher nicht weiter.
	 */
	if (!envp) {
		printf("Status: 500 Internal Server Error\n");
		goto end;
	}

	/* Wir liefern (wenn überhaupt) plaintext */
	printf("Content-Type: text/plain\n");
	
	/* Content-Type d. Request prüfen, nur x-www-form-urlencoded zulassen */
	contType = getenv("CONTENT_TYPE");
	if (!contType) {
		printf("Status: 400 Bad Request\n");
		goto end;
	}
	if (strcmp("application/x-www-form-urlencoded", contType) != 0) {
		printf("Status: 406 Not Acceptable\n");
		goto end;
	}

	/* Länge des request body */
	contLen = getenv("CONTENT_LENGTH");
	if (!contLen) {
		printf("Status: 400 Bad Request\n");
		goto end;
	}

	contSize = (size_t)strtonum(contLen, 0, INT_MAX, &errstr);
	/* Platz lassen für '\0' */
	if (errstr || contSize == INT_MAX) {
		printf("Status: 500 Internal Server Error\n");
		goto end;
	}

	_pInput = input = calloc(contSize+1, sizeof(char));
	if (!_pInput) {
		printf("Status: 500 Internal Server Error\n");
		goto end;
	}
	_pDecoded = decoded = calloc(contSize+1, sizeof(char));
	if (!_pDecoded) {
		printf("Status: 500 Internal Server Error\n");
		goto end;
	}

	passwdFile = fopen("/etc/mail/vpasswd", "r+");
	if (passwdFile == NULL) {
		printf("Status: 500 Internal Server Error\n");
		goto end;
	}

	/* CGI: Input (request body) kommt über stdin */
	scanf("%s", input);
	/* Content-Type ist 'x-www-form-urlencoded', das bedeutet,
	 * die Daten sind url-kodiert und müssen daher jetzt
	 * entsprechend dekodiert werden.
	 */
	//fprintf(stderr, "%s\n", input);
	// TODO evtl. fehlende Prüfungen, s. nach while (explizit wäre besser)
	input = url_decode(input);
	//fprintf(stderr, "%s\n", input);

	email = oldpw = newpw = NULL;
	while (input) {
		/* 
		 * Encoding 'x-www-form-urlencoded' bedeutet, dass die
		 * Form-Elemente als <key>=<value>-Paare kommen, die
		 * durch '&' verbunden sind.
		 */
		item = strsep(&input, "&");
		if (item) {
			key = strsep(&item, "=");
			if (key) {
				/* Relevante Keys finden und Values speichern. */
				if (strcmp("email", key) == 0) {
					email = item;
				} else if (strcmp("oldpw", key) == 0) {
					oldpw = item;
				} else if (strcmp("newpw", key) == 0) {
					newpw = item;
				} 
			}
		}
	}
	/* Die Values sind base64-kodiert und müssen daher noch dekodiert werden. */
	if (email) {
		if (b64_pton(email, decoded, contSize) >= 0) {
			email = strsep(&decoded, "@");
			if (strlen(email) < contSize) {
				email[strlen(email)+1] = '\0';
				email[strlen(email)] = ':';
				// TODO fehlende Prüfungen
				user = malloc(strlen(email)+1);
				strlcpy(user, email, strlen(email)+1);
				
				/* Benutzer in passwdfile suchen */
				fpos_t pos = 0;
				while ((passwdLineLen = getline(&passwdLine, &passwdLineSize, passwdFile)) != -1) {
					if (strstr(passwdLine, user) != NULL)
						break;
					fgetpos(passwdFile, &pos);
				}
				/* Benutzer wurde nicht gefunden */
				/* TODO: unterscheiden zw. error und eof */
				if (passwdLineLen == -1) {
					printf("Status: 422 Unprocessable Entity\n");
					goto end;

				}

				/* Altes PW des Benutzers überprüfen */
				if (oldpw) {
					memset(decoded, '\0', contSize+1);
					if (b64_pton(oldpw, decoded, contSize) >= 0) {
						// TODO fehlende Prüfungen
						sscanf(passwdLine, "%*[^:]:%s", hash);
						if (crypt_checkpass(decoded, hash) != 0) {
							printf("Status: 422 Unprocessable Entity\n");
							goto end;
						}
					} else {
						// TODO
					}
				} else {
					printf("Status: 422 Unprocessable Entity\n");
					goto end;
				}

				/* Neues PW des Benutzers speichern */
				if (newpw) {
					memset(decoded, '\0', contSize+1);
					if (b64_pton(newpw, decoded, contSize) >= 0) {
						// TODO fehlende Prüfungen
						crypt_newhash(decoded, "bcrypt,8", hash, sizeof(hash));
						fsetpos(passwdFile, &pos);
						fprintf(passwdFile, "%s%s\n", user, hash);
					} else {
						// TODO
					}
				} else {
					printf("Status: 422 Unprocessable Entity\n");
					goto end;
				}
			} else {
				printf("Status: 500 Internal Server Error\n");
				goto end;
			}
		} else {
			// TODO
		}
	} else {
		printf("Status: 422 Unprocessable Entity\n");
		goto end;
	}
	printf("Status: 204 No Content\n");

end:
	printf("\n");
	if (user)
		free(user);
	if (passwdLine)
		free(passwdLine);
	if (passwdFile)
		fclose(passwdFile);
	if (_pDecoded)
		free(_pDecoded);
	if (_pInput)
		free(_pInput);
	return (0);
}

char *
url_decode(char *url)
{
	char		*p, *q;
	char		 hex[3];
	unsigned long	 x;

	hex[2] = '\0';
	p = q = url;

	while (*p != '\0') {
		switch (*p) {
		case '%':
			/* Encoding character is followed by two hex chars */
			if (!(isxdigit((unsigned char)p[1]) &&
			    isxdigit((unsigned char)p[2])))
				return (NULL);

			hex[0] = p[1];
			hex[1] = p[2];

			/*
			 * We don't have to validate "hex" because it is
			 * guaranteed to include two hex chars followed by nul.
			 */
			x = strtoul(hex, NULL, 16);
			*q = (char)x;
			p += 2;
			break;
		default:
			*q = *p;
			break;
		}
		p++;
		q++;
	}
	*q = '\0';

	return (url);
}

