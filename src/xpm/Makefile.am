stock_images = \
	icon_clear.png \
	icon_edit.png \
	icon_start_large.png \
	icon_start_normal.png \
	icon_start_toolbar.png \
	icon_stop_large.png \
	icon_stop_normal.png \
	icon_stop_toolbar.png \
	icon_unlocked.png \
	icon_locked.png \
	icon_locked_large.png \
	icon_wizard.png \
	logo.png \
	pengo.png \
	tray_hit1.png \
	tray_hit2.png \
	tray_hit3.png \
	tray_hit4.png \
	tray_hit5.png

EXTRA_DIST = \
	$(stock_images)

noinst_HEADERS = \
	fortified-pixbufs.h

fortified-pixbufs.h: $(stock_images)
		-rm -f fortified-pixbufs.h
		var=`echo "$(stock_images)" | sed -e 's,\([^\.]*\)\.png,\1 \0,g'` ; \
		   echo $$var; \
		   gdk-pixbuf-csource --raw --build-list $$var > fortified-pixbufs.h
