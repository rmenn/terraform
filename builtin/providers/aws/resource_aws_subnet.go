package aws

import (
	"fmt"
	"log"
	"time"

	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/helper/schema"
	"github.com/mitchellh/goamz/ec2"
)

func resourceAwsSubnet() *schema.Resource {
	return &schema.Resource{
		Create: resourceAwsSubnetCreate,
		Read:   resourceAwsSubnetRead,
		Update: resourceAwsSubnetUpdate,
		Delete: resourceAwsSubnetDelete,

		Schema: map[string]*schema.Schema{
			"vpc_id": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
				Computed: true,
			},

			"cidr_block": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},

			"availability_zone": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
				ForceNew: true,
			},

			"map_public_ip_on_launch": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Computed: true,
			},

			"tags": tagsSchema(),
		},
	}
}

func resourceAwsSubnetCreate(d *schema.ResourceData, meta interface{}) error {
	ec2conn := meta.(*AWSClient).ec2conn

	createOpts := &ec2.CreateSubnet{
		AvailabilityZone: d.Get("availability_zone").(string),
		CidrBlock:        d.Get("cidr_block").(string),
		VpcId:            d.Get("vpc_id").(string),
	}

	resp, err := ec2conn.CreateSubnet(createOpts)

	if err != nil {
		return fmt.Errorf("Error creating subnet: %s", err)
	}

	// Get the ID and store it
	subnet := &resp.Subnet
	d.SetId(subnet.SubnetId)
	log.Printf("[INFO] Subnet ID: %s", subnet.SubnetId)

	// Wait for the Subnet to become available
	log.Printf("[DEBUG] Waiting for subnet (%s) to become available", subnet.SubnetId)
	stateConf := &resource.StateChangeConf{
		Pending: []string{"pending"},
		Target:  "available",
		Refresh: SubnetStateRefreshFunc(ec2conn, subnet.SubnetId),
		Timeout: 10 * time.Minute,
	}

	_, err = stateConf.WaitForState()

	if err != nil {
		return fmt.Errorf(
			"Error waiting for subnet (%s) to become ready: %s",
			d.Id(), err)
	}

	return resourceAwsSubnetUpdate(d, meta)
}

func resourceAwsSubnetRead(d *schema.ResourceData, meta interface{}) error {
	ec2conn := meta.(*AWSClient).ec2conn

	resp, err := ec2conn.DescribeSubnets([]string{d.Id()}, ec2.NewFilter())

	if err != nil {
		if ec2err, ok := err.(*ec2.Error); ok && ec2err.Code == "InvalidSubnetID.NotFound" {
			// Update state to indicate the subnet no longer exists.
			d.SetId("")
			return nil
		}
		return err
	}
	if resp == nil {
		return nil
	}

	subnet := &resp.Subnets[0]

	d.Set("vpc_id", subnet.VpcId)
	d.Set("availability_zone", subnet.AvailabilityZone)
	d.Set("cidr_block", subnet.CidrBlock)
	d.Set("map_public_ip_on_launch", subnet.MapPublicIpOnLaunch)
	d.Set("tags", tagsToMap(subnet.Tags))

	return nil
}

func resourceAwsSubnetUpdate(d *schema.ResourceData, meta interface{}) error {
	ec2conn := meta.(*AWSClient).ec2conn

	d.Partial(true)

	if err := setTags(ec2conn, d); err != nil {
		return err
	} else {
		d.SetPartial("tags")
	}

	if d.HasChange("map_public_ip_on_launch") {
		modifyOpts := &ec2.ModifySubnetAttribute{
			SubnetId:            d.Id(),
			MapPublicIpOnLaunch: true,
		}

		log.Printf("[DEBUG] Subnet modify attributes: %#v", modifyOpts)

		_, err := ec2conn.ModifySubnetAttribute(modifyOpts)

		if err != nil {
			return err
		} else {
			d.SetPartial("map_public_ip_on_launch")
		}
	}

	d.Partial(false)

	return resourceAwsSubnetRead(d, meta)
}

func resourceAwsSubnetDelete(d *schema.ResourceData, meta interface{}) error {
	ec2conn := meta.(*AWSClient).ec2conn

	log.Printf("[INFO] Deleting subnet: %s", d.Id())
	if _, err := ec2conn.DeleteSubnet(d.Id()); err != nil {
		ec2err, ok := err.(*ec2.Error)
		if ok && ec2err.Code == "InvalidSubnetID.NotFound" {
			return nil
		}

		return fmt.Errorf("Error deleting subnet: %s", err)
	}

	return nil
}

// SubnetStateRefreshFunc returns a resource.StateRefreshFunc that is used to watch a Subnet.
func SubnetStateRefreshFunc(conn *ec2.EC2, id string) resource.StateRefreshFunc {
	return func() (interface{}, string, error) {
		resp, err := conn.DescribeSubnets([]string{id}, ec2.NewFilter())
		if err != nil {
			if ec2err, ok := err.(*ec2.Error); ok && ec2err.Code == "InvalidSubnetID.NotFound" {
				resp = nil
			} else {
				log.Printf("Error on SubnetStateRefresh: %s", err)
				return nil, "", err
			}
		}

		if resp == nil {
			// Sometimes AWS just has consistency issues and doesn't see
			// our instance yet. Return an empty state.
			return nil, "", nil
		}

		subnet := &resp.Subnets[0]
		return subnet, subnet.State, nil
	}
}
