/*
 * ssh2.c
 *
 *  Incomplete open-ssh drop-in replacement.
 *
 *  Based on libssh2 example. Enhanced by volpol, uw.
 *
 *  Modifed:
 *		2013-05-31	support conncetion forwarding (tunneling) [uw]
 *
 *  TODO:
 *    Add reverse connection forwarding, using:
 *      LIBSSH2_LISTENER * libssh2_channel_forward_listen(LIBSSH2_SESSION *session, int port);
 *      LIBSSH2_CHANNEL * libssh2_channel_forward_accept(LIBSSH2_LISTENER *listener);
 */


#include <libssh2.h>
#include <libssh2_sftp.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>

#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>

#include <termios.h>
#include <signal.h>

#include "net.h"
#include "log.h"

#define AUTH_NONE	(1U<<0)
#define AUTH_PWD	(1U<<1)
#define AUTH_PKI	(1U<<2)
#define AUTH_KBD	(1U<<3)

static volatile sig_atomic_t winched;

static struct settings {
	const char *login;
	const char *hostname;
	const char *command;
	const char *public;
	const char *private;
	const char *term;
	const char *bindaddr;
	int port;
	int noxcmd;
	int nostdin;
	int background;
} config = {
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	0,
	0,
	0,
	0,
};

#ifdef WITH_TUNNEL
struct tunnel_spec {
	struct tunnel_spec *next;
	const char *bindaddr;
	int lport;
	const char *host;
	int port;
	int sock;
};

struct client {
	struct client *next, *prev;
	int sock;
	LIBSSH2_CHANNEL *channel;
};
#endif

static struct session_info {
	int sock;
	LIBSSH2_SESSION *session;
	LIBSSH2_CHANNEL *channel;
#ifdef WITH_TUNNEL
	struct tunnel_spec *ltunnel;
	struct client *lclient;
#endif
} sess = {
	-1,
	NULL,
	NULL,
#ifdef WITH_TUNNEL
	NULL,
	NULL,
#endif
};


static int do_askpass( const char *prompt, char *pass, int maxlen, int echo )
{
	struct termios options;
	char *p;
	int res = -1;

	fputs( prompt, stdout );
	if ( config.nostdin )
		return res;
	if ( !echo )
	{
		tcgetattr( 0, &options );
		options.c_lflag &= ~ECHO;
		tcsetattr( 0, TCSANOW, &options );
	}
	if ( fgets( pass, maxlen, stdin ) )
	{
		res = 0;
		while ( NULL != ( p = strchr( pass, '\r' ) )
			|| NULL != ( p = strchr( pass, '\n' ) ) )
			*p = '\0';
	}
	else
		*pass = '\0';
	if ( !echo )
	{
		tcgetattr( 0, &options );
		options.c_lflag |= ECHO;
		tcsetattr( 0, TCSANOW, &options );
		putc( '\n', stdout );
	}
	return res;
}

static void kbd_callback(const char *name, int name_len,
			 const char *instruction, int instruction_len,
			 int num_prompts, const LIBSSH2_USERAUTH_KBDINT_PROMPT *prompts,
			 LIBSSH2_USERAUTH_KBDINT_RESPONSE *responses,
			 void **abstract)
{
	WHOAMI;
	int i;
	char passwd[256];

	if ( name )
	{
		write( 1, name, name_len );
		putc( '\n', stdout );
	}
	if ( instruction )
	{
		write( 1, instruction, instruction_len );
		putc( '\n', stdout );
	}
	for ( i = 0; i < num_prompts; ++i )
	{
		if ( prompts[i].text )
			write( 1, prompts[i].text, prompts[i].length );
		do_askpass( "", passwd, sizeof passwd, prompts[i].echo );
		responses[i].text = strdup( passwd );
		responses[i].length = strlen( passwd );
	}
	(void)abstract;
}

static int do_auth( LIBSSH2_SESSION *session )
{
	char *userauthlist;
	const char *fingerprint;
	char hexfin[128] = "";
	char passwd[256];
	unsigned int auth = 0;
	int i, err = -1;

	/* TODO: we could check fingerprint against list of known hosts or wateva! */
	fingerprint = libssh2_hostkey_hash( session, LIBSSH2_HOSTKEY_HASH_SHA1 );
	for ( i = 0; i < 20; i++ )
		sprintf( hexfin + 2 * i, "%02X", (unsigned)((unsigned char)fingerprint[i]) );
	DPRINT( "Fingerprint: %s\n", hexfin );

	/* check what authentication methods are available */
	userauthlist = libssh2_userauth_list( session, config.login, strlen( config.login ) );
	if ( NULL == userauthlist )
	{
		if ( libssh2_userauth_authenticated( session ) )
		{
			auth = AUTH_NONE;
			DPRINT( "Authentication by method 'none' succeeded. Blame server admin.\n" );
		}
		else
		{
			DPRINT( "libssh2_userauth_list failed.\n" );
		}
		goto DONE;
	}
	DPRINT( "Authentication methods: %s\n", userauthlist );
	if ( strstr( userauthlist, "password" ) != NULL )
		auth |= AUTH_PWD;
	if ( strstr( userauthlist, "keyboard-interactive" ) != NULL )
		auth |= AUTH_KBD;
	if ( strstr( userauthlist, "publickey" ) != NULL )
		auth |= AUTH_PKI;

	if ( auth & AUTH_PKI )
	{
		DPRINT( "Trying authentication using public key\n" );
		err = libssh2_userauth_publickey_fromfile( session, config.login,
									config.public, config.private, NULL );
		if ( err == LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED )
		{
			sprintf( passwd, "Enter passphrase for key '%s':", config.private );
			do_askpass( passwd, passwd, sizeof passwd, 0 );
			err = libssh2_userauth_publickey_fromfile( session, config.login,
									config.public, config.private, passwd );
		}
		if ( 0 == err )
		{
			DPRINT( "Authentication by public key succeeded.\n" );
			goto DONE;
		}
		DPRINT( "Authentication by public key failed! (%d)\n", err );
		auth &= ~AUTH_PKI;
	}
	if ( auth & AUTH_PWD )
	{
		DPRINT( "Trying authentication using password\n" );
		sprintf( passwd, "Password for %s@%s:", config.login, config.hostname );
		do_askpass( passwd, passwd, sizeof passwd, 0 );
		err = libssh2_userauth_password( session, config.login, passwd );
		if ( 0 == err )
		{
			DPRINT( "Authentication by password succeeded.\n" );
			goto DONE;
		}
		DPRINT( "Authentication by password failed! (%d)\n", err );
		auth &= ~AUTH_PWD;
	}
    if ( auth & AUTH_KBD )
    {
		DPRINT( "Trying interactive authentication\n" );
        err = libssh2_userauth_keyboard_interactive( session, config.login, &kbd_callback );
        if ( 0 == err )
        {
            DPRINT( "Authentication by keyboard-interactive succeeded.\n" );
			goto DONE;
        }
        DPRINT( "Authentication by keyboard-interactive failed! (%d)\n", err );
        auth &= ~AUTH_KBD;
    }
DONE:
	return auth ? 0 : -1;
}

static void do_resize_pty( LIBSSH2_CHANNEL *channel )
{
	struct winsize tsize;
	WHOAMI;
	if ( channel && 0 == ioctl( 1, TIOCGWINSZ, &tsize ) )
		libssh2_channel_request_pty_size_ex( channel, tsize.ws_col, tsize.ws_row, 0, 0 );
	winched = 0;
}

static void handle_sigwinch( int sig )
{
	winched = 1;
	(void)sig;
}

#ifdef WITH_TUNNEL
static int add_tunnel( struct tunnel_spec **pt, char *s )
{
	WHOAMI;
	char *p = NULL;
	struct tunnel_spec *t = NULL;

	if ( NULL == ( t = malloc( sizeof *t ) ) )
		goto ERR;
	if ( NULL == ( p = strrchr( s, ':' ) ) || p == s )
		goto ERR;
	*p++ = '\0';
	t->port = atoi( p );
	if ( NULL == ( p = strrchr( s, ':' ) ) || p == s )
		goto ERR;
	*p++ = '\0';
	t->host = p;
	if ( NULL == ( p = strrchr( s, ':' ) ) )
	{	// bind to all interfaces by default, mimicking openssh's bevavior
		t->bindaddr = "*";
		t->lport = atoi( s );
	}
	else
	{
		if ( p == s )
			goto ERR;
		*p++ = '\0';
		t->bindaddr = s;
		t->lport = atoi( p );
	}
	t->sock = -1;
	t->next = *pt;
	*pt = t;
	DPRINT( "Tunnel: %s:%d:%s:%d\n", t->bindaddr, t->lport, t->host, t->port );
	return 0;
ERR:
	free( t );
	return -1;
}

static void remove_tunnels( struct tunnel_spec **pt )
{
	WHOAMI;
	struct tunnel_spec *t;

	while ( NULL != *pt )
	{
		t = *pt;
		*pt = t->next;
		if ( 0 <= t->sock )
			net_close( t->sock );
		free( t );
	}
}

static int register_tunnels( struct tunnel_spec *t )
{
	WHOAMI;
	for ( ; NULL != t; t = t->next )
	{
		if ( 0 > ( t->sock = net_open_server( t->lport, t->bindaddr ) ) )
		{
			fprintf( stderr, "Unable to listen on %s:%d\n", t->bindaddr, t->lport );
			return -1;
		}
		else
		{
			DPRINT( "Listening on %s:%d\n", t->bindaddr, t->lport );
		}
	}
	return 0;
}

static int add_client( struct client **lp, struct tunnel_spec *t, LIBSSH2_SESSION *session )
{
	int sock = -1;
	struct client *cp = NULL;
	LIBSSH2_CHANNEL *channel;

	if ( 0 > ( sock = net_accept( t->sock ) ) )
		goto ERR;
#ifdef USE_STRICT_NONBLOCK
	/* Clogged clients will get no mercy. */
	int flags;
    if ( -1 == ( flags = fcntl( sock, F_GETFL, 0 ) ) )
        flags = 0;
    if ( 0 != fcntl( sock, F_SETFL, flags | O_NONBLOCK ) )
		goto ERR;
#else
	/* We're not the clients' input buffer extension, but we'll grant them a
	grace period of up to 2 seconds to get their act together. Aren't we nice? */
	struct timeval to = { 2, 0 };
	if ( 0 != setsockopt( sock, SOL_SOCKET, SO_SNDTIMEO, &to, sizeof to ) )
		goto ERR;
#endif
	if ( NULL == ( cp = malloc( sizeof *cp ) ) )
		goto ERR;
	if ( NULL == ( channel = libssh2_channel_direct_tcpip( session, t->host, t->port ) )
			&& LIBSSH2_ERROR_EAGAIN == libssh2_session_last_errno( session ) )
	{
		/* Why, oh, why does the first call to libssh2_channel_direct_tcpip()
		   spuriously  fail with 'WOULD BLOCK' every so often? */
		usleep( 50000 );	// Uck! Yuck! Bleah!
		if ( NULL == ( channel = libssh2_channel_direct_tcpip( session, t->host, t->port ) ) )
		{
			char *msg;
			libssh2_session_last_error( session, &msg, NULL, 0 );
			fprintf( stderr, "libssh2_channel_direct_tcpip(): %s\n", msg );
			goto ERR;
		}
	}
	libssh2_channel_set_blocking( channel, 0 );
	cp->sock = sock;
	cp->channel = channel;
	cp->prev = NULL;
	cp->next = *lp;
	if ( cp->next )
		cp->next->prev = cp;
	*lp = cp;
	return 0;
ERR:
	net_close( sock );
	free( cp );
	return -1;
}

static void del_client( struct client **lp, struct client *cp )
{
	libssh2_channel_free( cp->channel );
	net_close( cp->sock );
	if ( cp->next )
		cp->next->prev = cp->prev;
	if ( cp->prev )
		cp->prev->next = cp->next;
	if ( cp == *lp )
		*lp = cp->next;
	free( cp );
}
#endif

static int pump2chan( int fd, LIBSSH2_CHANNEL *channel )
{
	int nread;
	char buf[4*1024];

	if ( 0 < ( nread = read( fd, buf, sizeof buf ) ) )
	{
		//DPRINT( "%d bytes fd(%d) -> channel\n", nread, fd );
		if ( nread != libssh2_channel_write( channel, buf, nread ) )
			goto FAIL;
	}
	else if ( 0 == nread || ( EAGAIN != errno && EWOULDBLOCK != errno ) )
		goto FAIL;
	return 0;
FAIL:
	libssh2_channel_send_eof( channel );
	return -1;
}

static int pump2fd( int fd, LIBSSH2_CHANNEL *channel )
{
	int nread;
	char buf[4*1024];

	while ( 0 < ( nread = libssh2_channel_read( channel, buf, sizeof buf ) ) )
	{
		//DPRINT( "%d bytes channel -> fd(%d)\n", nread, fd );
		if ( nread != write( fd, buf, nread ) )
			goto FAIL;
	}
	if ( 0 == nread && libssh2_channel_eof( channel ) )
		goto FAIL;
	else if ( 0 > nread && LIBSSH2_ERROR_EAGAIN != nread )
		goto FAIL;
	return 0;
FAIL:
	return -1;
}

static void do_session( void )
{
	struct termios oraw, oback;
	fd_set rfds;
	struct timeval tv;
	int fdmax, nfd, nfdrdy;
	int eof = 0;

	if ( !config.nostdin )
	{
		tcgetattr( 0, &oback );
		memcpy( &oraw, &oback, sizeof oraw );
		cfmakeraw( &oraw );
		tcsetattr( 0, TCSANOW, &oraw );
	}
	/* Set channel non-blocking, otherwise we might get stuck in
	 * the libssh2_channel_read loop - select operates on the socket,
	 * but we read from a channel!
	 */
	libssh2_channel_set_blocking( sess.channel, 0 );

	while ( !eof )
	{
		if ( winched )
			do_resize_pty( sess.channel );

		FD_ZERO( &rfds );
		if ( !config.nostdin )
			FD_SET( 0, &rfds );
		FD_SET( sess.sock, &rfds );
		fdmax = sess.sock;

#ifdef WITH_TUNNEL
		struct tunnel_spec *t;
		struct client *c, *cnext;
		for ( t = sess.ltunnel; NULL != t; t =  t->next )
		{
			FD_SET( t->sock, &rfds );
			if ( fdmax < t->sock )
				fdmax = t->sock;
		}
		for ( c = sess.lclient; NULL != c; c =  c->next )
		{
			if ( 0 <= c-> sock )
			{
				FD_SET( c->sock, &rfds );
				if ( fdmax < c->sock )
					fdmax = c->sock;
			}
		}
#endif

		tv.tv_sec = 1;
		tv.tv_usec = 0;
		nfdrdy = select( fdmax + 1, &rfds, NULL, NULL, &tv );

		if ( 0 > nfdrdy )
		{	// error
			if ( EINTR != errno )
				eof = 1;
		}
		else if ( 0 == nfdrdy )
		{ 	// timeout
		}
		else
		{
			nfd = 0;
			// forward stdin data
			if ( !config.nostdin && FD_ISSET( 0, &rfds ) )
			{
				if ( 0 != pump2chan( 0, sess.channel ) )
				{
					eof = 1;
					continue;
				}
				if ( ++nfd >= nfdrdy )
					continue;
			}
			// forward ssh channel data
			if ( FD_ISSET( sess.sock, &rfds ) )
			{
				// poll interactive session channel
				if ( /* !config.background && */ 0 != pump2fd( 1, sess.channel ) )
				{
					eof = 1;
					continue;
				}
#ifdef WITH_TUNNEL
				// poll tunnel channels for data
				for ( c = sess.lclient; NULL != c; c = cnext )
				{
					cnext = c->next;
					if ( 0 != pump2fd( c->sock, c->channel ) )
					{
						DPRINT( "pump2fd failed.\n" );
						del_client( &sess.lclient, c );
					}
				}
#endif
				if ( ++nfd >= nfdrdy )
					continue;
			}
#ifdef WITH_TUNNEL
			// check local client sockets for data
			for ( c = sess.lclient; NULL != c && nfd < nfdrdy; c = cnext )
			{
				cnext = c->next;
				if ( FD_ISSET( c->sock, &rfds ) )
				{
					if ( 0 != pump2chan( c->sock, c->channel ) )
					{
						DPRINT( "pump2chan failed.\n" );
						del_client( &sess.lclient, c );
					}
					++nfd;
				}
			}
			// check listener sockets for incoming connections
			for ( t = sess.ltunnel; NULL != t && nfd < nfdrdy; t =  t->next )
			{
				if ( FD_ISSET( t->sock, &rfds ) )
				{
					if ( 0 != add_client( &sess.lclient, t, sess.session ) )
					{
						DPRINT( "add_client failed!\n" );
					}
					++nfd;
				}
			}
#endif
		}
	}	// while ( !eof )

#ifdef WITH_TUNNEL
	// shutdown all tunnel clients
	while ( NULL != sess.lclient )
		del_client( &sess.lclient, sess.lclient );
#endif
	if ( !config.nostdin )
		tcsetattr( 0, TCSANOW, &oback );
}

static void usage( const char *me )
{
	const char *p;
	if ( NULL != ( p = strrchr( me, '/' ) ) )
		me = ++p;
	fprintf( stderr, "Usage: %s [options] [user@]hostname [command]\n", me );
	fprintf( stderr,
		" Options:\n"
		"  -b bind address\n"
		"  -i identity_file\n"
		"  -l login_name\n"
		"  -p hostport\n"
#ifdef WITH_TUNNEL
		"  -L [bind_address:]port:host:hostport\n"
		"       Forward conections on local port to hostport on host.\n"
#endif
		"  -N   Do not execute a remote command.\n"
		"  -n   Prevent reading from stdin.\n"
		"  -f   Go to background just before command execution.\n"
	);
}

static int do_config( int argc, char *argv[] )
{
	int opt;
	char keyf[256];
	const char *ostr = "-:hb:i:l:p:fnN"
#ifdef WITH_TUNNEL
		"L:"
#endif
		;

	if ( NULL == ( config.term = getenv( "TERM" ) ) )
		config.term = "vanilla";
	config.login = getenv( "USER" );
	config.port = 22;

	while ( -1 != ( opt = getopt( argc, argv, ostr ) ) )
	{
		switch ( opt )
		{
		case 1:
			if ( NULL == config.hostname )
			{
				char *at;
				config.hostname = optarg;
				if ( NULL != ( at = strchr( config.hostname, '@' ) ) )
				{
					*at++ = 0;
					config.login = config.hostname;
					config.hostname = at;
				}
			}
			else if ( NULL == config.command )
				config.command = optarg;
			else
			{
				fprintf( stderr, "Excess non-option argument '%s'\n", optarg );
				return -1;
			}
			break;
		case 'b':
			config.bindaddr = optarg;
			break;
		case 'i':
			config.private = optarg;
			config.public = NULL;
			break;
		case 'l':
			config.login = optarg;
			break;
		case 'N':
			config.noxcmd = 1;
			break;
		case 'n':
			config.nostdin = 1;
			break;
		case 'f':
			config.background = 1;
			break;
		case 'p':
			config.port = atoi( optarg );
			break;
#ifdef WITH_TUNNEL
		case 'L':
			if ( 0 != add_tunnel( &sess.ltunnel, optarg ) )
				return -1;
			break;
#endif
		case ':':
			fprintf( stderr, "Missing argument for option '%c'\n", optopt );
			return -1;
			break;
		case '?':
		default:
			fprintf( stderr, "Unrecognized option '%c'\n", optopt );
		case 'h':
			return -1;
			break;
		}
	}
	if ( !config.hostname || !*config.hostname )
	{
		fprintf( stderr, "No host specified\n" );
		return -1;
	}
	if ( !config.login || !*config.login )
	{
		fprintf( stderr, "No user name specified\n" );
		return -1;
	}
	if ( config.private == NULL )
	{	// Check for standard identities
		int i;
		const char *ids[] = {
			"id_rsa",
			"id_dsa",
			"id_ecdsa",
			NULL
		};
		for ( i = 0; ids[i] && NULL == config.private; ++i )
		{
			snprintf( keyf, sizeof keyf, "%s/.ssh/%s", getenv( "HOME" ), ids[i] );
			if ( 0 == access( keyf, R_OK ) )
			{
				config.private = strdup( keyf );
				snprintf( keyf, sizeof keyf, "%s/.ssh/%s.pub", getenv( "HOME" ), ids[i] );
				if ( 0 == access( keyf, R_OK ) )
					config.public = strdup( keyf );
				DPRINT( "Using default identity '%s'\n", config.private );
			}
		}
		if ( NULL == config.private )
		{
			DPRINT( "No standard identity found\n" );
		}
	}
	else
	{
		DPRINT( "Using specified identity\n" );
	}
	return 0;
}


static int daemonize( void )
{
    pid_t pid, sid;

    if ( getppid() == 1 )
		return 0;
    pid = fork();
    if ( pid < 0 )
		return -1;
    if ( pid > 0 )
        exit( EXIT_SUCCESS );
    umask( 0 );
    sid = setsid();
    if ( sid < 0 )
		return -1;
    if ( chdir( "/" ) < 0 )
   		return -1;
    freopen( "/dev/null", "r", stdin );
    freopen( "/dev/null", "w", stdout );
    freopen( "/dev/null", "w", stderr );
    return 0;
}


int main( int argc, char *argv[] )
{
	int err = -1;

	if ( 0 != do_config( argc, argv ) )
	{
		usage( argv[0] );
		goto ssh2_no_init;
	}
	DPRINT( "Connecting to %s on port %d as %s\n",
			config.hostname, config.port, config.login );
	DPRINT( "P|P:%s|%s\n", config.public, config.private );
	if ( 0 != ( err = libssh2_init( 0 ) ) )
	{
		fprintf( stderr, "libssh2 initialization failed (%d)\n", err );
		goto ssh2_no_init;
	}
	if ( 0 > ( sess.sock = net_open_client( config.hostname, config.port, config.bindaddr ) ) )
	{
		err = -1;
		fprintf( stderr, "Failed to connect\n" );
		goto net_no_connect;
	}
#ifdef WITH_TUNNEL
	if ( 0 != register_tunnels( sess.ltunnel ) )
	{
		err = -1;
		goto ssh2_no_session;
	}
#endif
	/* Create a session instance and start it up. This will trade welcome
	 * banners, exchange keys, and setup crypto, compression, and MAC layers
	 */
	if ( NULL == ( sess.session = libssh2_session_init() ) )
	{
		err = -1;
		fprintf( stderr, "Failure to create SSH session\n" );
		goto ssh2_no_session;
	}
	if ( 0 != ( err = libssh2_session_handshake( sess.session, sess.sock ) ) )
	{
		fprintf( stderr, "Failure establishing SSH session (%d)\n", err );
		goto ssh2_no_handshake;
	}
	if ( 0 > do_auth( sess.session ) )
	{
		err = -1;
		fprintf( stderr, "Unable to authenticate\n" );
		goto ssh2_no_channel;
	}
	if ( NULL == ( sess.channel = libssh2_channel_open_session( sess.session ) ) )
	{
		err = -1;
		fprintf( stderr, "Unable to open a channel\n" );
		goto ssh2_no_channel;
	}
	if ( 0 != ( err = libssh2_channel_request_pty( sess.channel, config.term ) ) )
	{
		fprintf( stderr, "Failed requesting pty (%d)\n", err) ;
		goto ssh2_no_pty;
	}

	do_resize_pty( sess.channel );
	signal( SIGWINCH, handle_sigwinch );
	if ( config.background )
	{
		DPRINT( "going to background" );
		config.nostdin = 1;
		if ( 0 != daemonize() )
		{
			fprintf( stderr, "Switching to background failed!\n" );
			goto ssh2_no_shell;
		}
	}
	if ( !config.noxcmd )
	{
		/* Start process on pty */
		err = config.command
				? libssh2_channel_exec( sess.channel, config.command )
				: libssh2_channel_shell( sess.channel );
		if ( 0 != err )
		{
			fprintf( stderr, "Unable to execute command on allocated pty (%d)\n", err );
			goto ssh2_no_shell;
		}
	}

	/* we're all set, let's boogie: */
	signal( SIGINT, SIG_IGN );
	signal( SIGSTOP, SIG_IGN );
	do_session();
	signal( SIGINT, SIG_DFL );
	signal( SIGSTOP, SIG_DFL );

ssh2_no_shell:
	signal( SIGWINCH, SIG_DFL );

ssh2_no_pty:
	if ( sess.channel )
	{
		libssh2_channel_free( sess.channel );
		sess.channel = NULL;
	}

ssh2_no_handshake:
	libssh2_session_disconnect( sess.session, NULL );

ssh2_no_channel:
	libssh2_session_free( sess.session );

ssh2_no_session:
	net_close( sess.sock );
#ifdef WITH_TUNNEL
	remove_tunnels( &sess.ltunnel );
#endif

net_no_connect:
	libssh2_exit();

ssh2_no_init:
	return err;
}
