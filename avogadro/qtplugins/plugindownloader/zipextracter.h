#include "archive.h"
#include "archive_entry.h"
#include <string>
namespace Avogadro {

namespace QtPlugins {

class ZipExtracter {

public:
	ZipExtracter();
	~ZipExtracter();
	static char* convert(const std::string&);
	static int copy_data(struct archive *ar, struct archive *aw);
	static int extract(const char *filename, const char* extractdir, const char* filefolder);

};
}
}
