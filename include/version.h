#ifndef _TDTP_VERSION_H_
#define _TDTP_VERSION_H_

#define TDTP_MAJOR_VER "0"
#define TDTP_MINOR_VER "0"
#define TDTP_PATCH_VER "1"

#ifdef TDTP_BD
#define TDTP_VER TDTP_MAJOR_VER "." TDTP_MINOR_VER "." TDTP_PATCH_VER " (" TDTP_BD ")"
#else
#define TDTP_VER TDTP_MAJOR_VER "." TDTP_MINOR_VER "." TDTP_PATCH_VER
#endif /* TDTP_BD */

#endif /* _TDTP_VERSION_H_ */
