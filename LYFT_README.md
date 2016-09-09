# Deploying the Lyft bless lambda

1. Pull requests should be made to the `lyft_base` branch. This branch includes the necessary `aws_lambda_libs` and `lambda_configs` for building the lambda.
1. Run `make publish`
1. Log into the aws console and assume the `admin@lyft-security` role.
1. Go to the lambda and upload the ZIP that was made from `make publish`.
1. The following steps are not yet available to do in the AWS console so they need to be done via command line. Run `mfa.sh --role admin@security`.
1. Publish the latest uploaded zip as a new version: `aws lambda publish-version --function-name arn:aws:lambda:REGION_HERE:ACCOUNT_NUMBER_HERE:function:lyft_bless --region REGION_HERE`
1. Create an alias for the latest version: `aws lambda create-alias --function-name arn:aws:lambda:REGION_HERE:ACCOUNT_NUMBER_HERE:function:lyft_bless --name ALIAS_NAME --function-version VERSION_NUMBER --region REGION_HERE` - the alias name should be a version e.g. `PROD-1-2`.
1. Repeat these steps for all the regions the lambda is in (us-east-1, us-west-2)
1. Add a PR to the blessclient to update the version of lambda called on the user side.
