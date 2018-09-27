trap { Write-Error $_; Exit 1 }

pip install twine
twine upload --repository-url  https://test.pypi.org/legacy/ dist/*
