gladedir = $(datadir)/fortified/glade/
SUBDIRS = xpm

AM_CPPFLAGS = \
	$(WARN_CFLAGS) \
	@FORTIFIED_CFLAGS@ \
	-DG_LOG_DOMAIN=\"Fortified\" \
	-DFORTIFIED_RULES_DIR=\"@sysconfdir@\" \
	-DGNOMELOCALEDIR=\""$(datadir)/locale"\" \
	-DGLADEDIR=\""$(datadir)/fortified/glade"\"

bin_PROGRAMS = fortified

fortified_SOURCES = \
	fortified.c	\
	gui.c		\
	util.c		\
	logread.c	\
	menus.c  	\
	wizard.c 	\
	wizard-choices.c \
	service.c	\
	preferences.c	\
	scriptwriter.c	\
	savelog.c	\
	netfilter-script.c \
	hitview.c	\
	eggtrayicon.c	\
	tray.c		\
	dhcp-server.c	\
	statusview.c	\
	policyview.c	\
	globals.h	\
	fortified.h	\
	gui.h		\
	util.h		\
	logread.h	\
	menus.h  	\
	wizard.h 	\
	wizard-choices.h \
	service.h	\
	preferences.h	\
	scriptwriter.h	\
	savelog.h	\
	netfilter-script.h \
	hitview.h	\
	eggtrayicon.h	\
	tray.h		\
	dhcp-server.h	\
	statusview.h	\
	policyview.h

glade_DATA = \
	preferences.glade

fortified_LDADD = @FORTIFIED_LIBS@

EXTRA_DIST = $(glade_DATA)
