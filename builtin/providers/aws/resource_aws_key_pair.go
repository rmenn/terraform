package aws

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"

	"github.com/awslabs/aws-sdk-go/aws"
	awsGoEC2 "github.com/awslabs/aws-sdk-go/gen/ec2"
)

func resourceAwsKeyPair() *schema.Resource {
	return &schema.Resource{
		Create: resourceAwsKeyPairCreate,
		Read:   resourceAwsKeyPairRead,
		Update: nil,
		Delete: resourceAwsKeyPairDelete,

		Schema: map[string]*schema.Schema{
			"key_name": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"public_key": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"fingerprint": &schema.Schema{
				Type:     schema.TypeString,
				Computed: true,
			},
		},
	}
}

func resourceAwsKeyPairCreate(d *schema.ResourceData, meta interface{}) error {
	ec2conn := meta.(*AWSClient).awsEC2conn

	keyName := d.Get("key_name").(string)
	publicKey := d.Get("public_key").(string)
	req := &awsGoEC2.ImportKeyPairRequest{
		KeyName:           aws.String(keyName),
		PublicKeyMaterial: []byte(publicKey),
	}
	resp, err := ec2conn.ImportKeyPair(req)
	if err != nil {
		return fmt.Errorf("Error import KeyPair: %s", err)
	}

	d.SetId(*resp.KeyName)
	return nil
}

func resourceAwsKeyPairRead(d *schema.ResourceData, meta interface{}) error {
	ec2conn := meta.(*AWSClient).awsEC2conn

	req := &awsGoEC2.DescribeKeyPairsRequest{
		KeyNames: []string{d.Id()},
	}
	resp, err := ec2conn.DescribeKeyPairs(req)
	if err != nil {
		return fmt.Errorf("Error retrieving KeyPair: %s", err)
	}

	for _, keyPair := range resp.KeyPairs {
		if *keyPair.KeyName == d.Id() {
			d.Set("key_name", keyPair.KeyName)
			d.Set("fingerprint", keyPair.KeyFingerprint)
			return nil
		}
	}

	return fmt.Errorf("Unable to find key pair within: %#v", resp.KeyPairs)
}

func resourceAwsKeyPairDelete(d *schema.ResourceData, meta interface{}) error {
	ec2conn := meta.(*AWSClient).awsEC2conn

	err := ec2conn.DeleteKeyPair(&awsGoEC2.DeleteKeyPairRequest{
		KeyName: aws.String(d.Id()),
	})
	return err
}
