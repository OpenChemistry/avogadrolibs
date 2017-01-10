#include "archive.h"
#include "archive_entry.h"

namespace Avogadro {

namespace QtPlugins {

class ZipExtracter {

public:
	ZipExtracter();
	~ZipExtracter();
	static int copy_data(struct archive *ar, struct archive *aw);
	static int extract(const char *filename);

};
}
}
