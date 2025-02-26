# TimeStamp Authority Client PQ

## License

The software in this repo uses iText and thus is distributed under AGPLv3 license which can be found in the LICENSE.txt file.
Furthermore, iText has specific restrictions that can be found [here](https://itextpdf.com/how-buy/AGPLv3-license).
The contents of this package can be found at [https://github.com/EntrustCorporation/PQ-TSA-Client-Software](https://github.com/EntrustCorporation/PQ-TSA-Client-Software)

## Pre-requisites

This client application is developed with Java thus the requirements are the following:

* Java 11 or greater.
* Maven 3.6.3 or greater.

## Compilation

To compile the application Maven is used. The `pom.xml` file includes libraries and dependencies:

```bash
mvn clean package
```

Compiled classes will be created automatically at the `target` directory

## Execution

To run the application execute the `pdfstamper.sh` script.

### Usage

```bash
./pdfstamper.sh
```

Will show the usage information of the application.

### Verify PDF signatures

```bash
./pdfstamper.sh signed_document.pdf
```

Verifies the integrity of all signatures included in the provided PDF document.

### Add a timestamp to a PDF

```bash
./pdfstamper.sh signed_document.pdf updated_document.pdf config/configuration.json
```

Verifies the integrity of all signatures included in the provided PDF document and includes a new timestamp using the TSA configured in the `config/configuration.json` file.

## Configuration

The behavior to request a new timestamp can be configured through the config file that is located at: `config/configuration.json` the supported fields are:

* **tsa.url:** URL of the TSA to request the timestamp.
* **tsa.reservedPdfTimeStampSize:** Size in bytes to reserve in the PDF document to attach the requested timestamp.

## Package PQ TSA Client for distribution

```sh
tar -zvcf entrust-pq-tsa-client-1.2.1.tar.gz src pom.xml README.md config LICENSE.txt pdfstamper.sh
```
