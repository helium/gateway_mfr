# gateway_mfr

## Introduction

The gateway_mfr application provisions an attached ECC508/ECC608 for use as
part of a Helium hotspot. 

It does this by configuring and locking the ECC configuration fields and then
generating the miner key in slot 0. 

The public part of the miner key needs to be captured from the output of this
application and supplied as part of the data required to get into the Helium
Onboarding Server if gateway add and assert location transactions are to be
paid for on behalf of the user.

This applications should be used as part of a manufacturing image that does
_NOT_ include the Helium miner software and is solely used for testing and provisioning
the built hotspot before setting up the production miner image. 

## Usage

1. Build the application into the manufacturing QA/provisioning image. This will
   involve including erlang 22.x for running the application on the target
   hardware as well as the production build of the application. 

   A production build of the application can be built using:

   ```shell
    make release
   ```

   This will leave the application in `./_build/prod/rel`. The following steps
   will assume the application to be installed in `/gateway`.

2. As part of the provisioning/QA steps start and provision the ECC:

    ```shell
    /gateway/bin/gateway_mfr start
    /gateway/bin/gateway_mfr ecc provision
    ```

    This will configure the ECC, generate the miner key and output it to stdout.
    Capture this output and collect it and other required information for use by
    the Onboarding Server.

    If you need the extract the onboarding/miner key at a later stage you can run:

    ```shell
    /gateway/bin/gateway_mfr ecc onboarding
    ```

3. To verify that the ECC is configured correctly you can run a final test cycle as part of the QA steps:

    ```shell
    /gateway/bin/gateway_mfr ecc test
    ```

    This will output a table with all executed ECC tests and their results. 

The ECC is now configured for production use. The production image, including
the Helium miner can be installed and started. If configured correctly the miner
software will use the configured key in slot 0 as the miner key and use the ECC
for secure transaction signing. 