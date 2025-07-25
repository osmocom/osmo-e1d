#pragma once

#define LIBOSMO_OCTOI_VERSION {{VERSION}}
#define LIBOSMO_OCTOI_VERSION_STR "{{VERSION}}"

#define LIBOSMO_OCTOI_VERSION_MAJOR {{VERSION_MAJOR}}
#define LIBOSMO_OCTOI_VERSION_MINOR {{VERSION_MINOR}}
#define LIBOSMO_OCTOI_VERSION_PATCH {{VERSION_PATCH}}

#define LIBOSMO_OCTOI_VERSION_GREATER_EQUAL(major, minor, patch) \
	(LIBOSMO_OCTOI_VERSION_MAJOR > (major) || \
	 (LIBOSMO_OCTOI_VERSION_MAJOR == (major) && \
	  LIBOSMO_OCTOI_VERSION_MINOR > (minor)) || \
	 (LIBOSMO_OCTOI_VERSION_MAJOR == (major) && \
	  LIBOSMO_OCTOI_VERSION_MINOR == (minor) && \
	  LIBOSMO_OCTOI_VERSION_PATCH >= (patch)))
