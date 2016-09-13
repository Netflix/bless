# Lyft BLESS runbook

# Service summary

BLESS is a lambda that issues certificates to users for SSH access into Lyft instances. The blessclient (a Python script on each engineer’s laptop), is invoked every time a user attempts to SSH. The bless lambda is invoked via the client whenever the user’s current certificate is expired.

# Dashboards

Coming soon.

# Alarms

Coming soon.

# Oncall

BLESS is maintained by the security team, and oncall is handled by the security team pagerduty rotation.

# Deploying

1. Pull requests should be made to the `lyft_base` branch. This branch includes the necessary `aws_lambda_libs` and `lambda_configs` for building the lambda.
1. Run `make publish`
1. Log into the aws console and assume the `admin@lyft-security` role.
1. Go to the lambda and upload the ZIP that was made from `make publish`.
1. The following steps are not yet available to do in the AWS console so they need to be done via command line. Run `mfa.sh --role admin@security`.
1. Publish the latest uploaded zip as a new version: `aws lambda publish-version --function-name arn:aws:lambda:REGION_HERE:ACCOUNT_NUMBER_HERE:function:lyft_bless --region REGION_HERE`
1. Create an alias for the latest version: `create-alias --function-name arn:aws:lambda:REGION_HERE:ACCOUNT_NUMBER_HERE:function:lyft_bless --name ALIAS_NAME--function-version VERSION_NUMBER --region REGION_HERE` - the alias name should be a version e.g. `PROD-1-2`.
1. Repeat these steps for all the regions the lambda is in (us-east-1, us-west-2).
1. Test that the new lambda version works by testing the new alias on your machine.
1. Add a PR to the blessclient to update the version of lambda called on the user side.

## Schedule

Lyft BLESS can be deployed any time during business hours (M-F 9 AM - 5 PM)

## Reverting a BLESS deploy

The lambda is versioned and each version has an alias (e.g. PROD-1-1). If you deploy the lambda, you should check that the new lambda version works and is compatible with the latest version of the blessclient. When you know it is working, make a PR to blessclient to update the alias there. To rollback to a previous version, create a PR in blessclient to revert to a previous alias.

# Internal dependencies

None

# 3rd party dependencies

AWS:

* KMS
* IAM
* Lambda

Any outages in these products should be escalated to our AWS representative.

# Datastore dependencies

None
