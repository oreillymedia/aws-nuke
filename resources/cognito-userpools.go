package resources

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/rebuy-de/aws-nuke/v2/pkg/config"
)

type CognitoUserPool struct {
	svc  *cognitoidentityprovider.CognitoIdentityProvider
	name *string
	id   *string

	featureFlags config.FeatureFlags
}

func init() {
	register("CognitoUserPool", ListCognitoUserPools)
}

func ListCognitoUserPools(sess *session.Session) ([]Resource, error) {
	svc := cognitoidentityprovider.New(sess)
	resources := []Resource{}

	params := &cognitoidentityprovider.ListUserPoolsInput{
		MaxResults: aws.Int64(50),
	}

	for {
		output, err := svc.ListUserPools(params)
		if err != nil {
			return nil, err
		}

		for _, pool := range output.UserPools {
			resources = append(resources, &CognitoUserPool{
				svc:  svc,
				name: pool.Name,
				id:   pool.Id,
			})
		}

		if output.NextToken == nil {
			break
		}

		params.NextToken = output.NextToken
	}

	return resources, nil
}

func (f *CognitoUserPool) DisableDeletionProtection() error {

	output, err := f.svc.DescribeUserPool(&cognitoidentityprovider.DescribeUserPoolInput{
		UserPoolId: f.id,
	})
	if err != nil {
		return err
	}
	_, err = f.svc.UpdateUserPool(&cognitoidentityprovider.UpdateUserPoolInput{
		UserPoolId:             f.id,
		DeletionProtection:     aws.String("INACTIVE"),
		AutoVerifiedAttributes: output.UserPool.UserAttributeUpdateSettings.AttributesRequireVerificationBeforeUpdate,
	})
	if err != nil {
		return err
	}
	return nil
}

func (f *CognitoUserPool) FeatureFlags(ff config.FeatureFlags) {
	f.featureFlags = ff
}

func (f *CognitoUserPool) Filter() error {
	return nil
}

func (f *CognitoUserPool) Remove() error {
	params := &cognitoidentityprovider.DeleteUserPoolInput{
		UserPoolId: f.id,
	}
	_, err := f.svc.DeleteUserPool(params)
	if err != nil {
		if f.featureFlags.DisableDeletionProtection.CognitoUserPool {
			awsErr, ok := err.(awserr.Error)
			if ok && awsErr.Code() == "InvalidParameterException" &&
				awsErr.Message() == "The user pool cannot be deleted because "+
					"deletion protection is activated. Deletion protection must be "+
					"inactivated first." {
				err = f.DisableDeletionProtection()
				if err != nil {
					return err
				}
				_, err := f.svc.DeleteUserPool(params)
				if err != nil {
					return err
				}
				return nil
			}
		}
		return err
	}
	return nil
}

func (f *CognitoUserPool) String() string {
	return *f.name
}
