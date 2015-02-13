package aws

import (
	"log"
	"strings"
	"time"

	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/helper/schema"
	"github.com/mitchellh/goamz/route53"

	awsGo "github.com/awslabs/aws-sdk-go/aws"
	awsr53 "github.com/awslabs/aws-sdk-go/gen/route53"
)

func resourceAwsRoute53Zone() *schema.Resource {
	return &schema.Resource{
		Create: resourceAwsRoute53ZoneCreate,
		Read:   resourceAwsRoute53ZoneRead,
		Delete: resourceAwsRoute53ZoneDelete,

		Schema: map[string]*schema.Schema{
			"name": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},

			"zone_id": &schema.Schema{
				Type:     schema.TypeString,
				Computed: true,
			},
		},
	}
}

func resourceAwsRoute53ZoneCreate(d *schema.ResourceData, meta interface{}) error {
	r53 := meta.(*AWSClient).awsr53Conn

	comment := &awsr53.HostedZoneConfig{Comment: awsGo.String("Managed by Terraform")}
	req := &awsr53.CreateHostedZoneRequest{
		Name:             awsGo.String(d.Get("name").(string)),
		HostedZoneConfig: comment,
		CallerReference:  awsGo.String(time.Now().Format(time.RFC3339Nano)),
	}
	log.Printf("[DEBUG] Creating Route53 hosted zone: %s", req.Name)
	resp, err := r53.CreateHostedZone(req)
	if err != nil {
		return err
	}

	// Store the zone_id
	zone := route53.CleanZoneID(*resp.HostedZone.ID)
	d.Set("zone_id", zone)
	d.SetId(zone)

	// Wait until we are done initializing
	wait := resource.StateChangeConf{
		Delay:      30 * time.Second,
		Pending:    []string{"PENDING"},
		Target:     "INSYNC",
		Timeout:    10 * time.Minute,
		MinTimeout: 2 * time.Second,
		Refresh: func() (result interface{}, state string, err error) {
			changeRequest := &awsr53.GetChangeRequest{
				ID: awsGo.String(CleanChangeID(*resp.ChangeInfo.ID)),
			}
			return resourceAwsGoRoute53Wait(r53, changeRequest)
		},
	}
	_, err = wait.WaitForState()
	if err != nil {
		return err
	}
	return nil
}

func resourceAwsRoute53ZoneRead(d *schema.ResourceData, meta interface{}) error {
	r53 := meta.(*AWSClient).awsr53Conn
	_, err := r53.GetHostedZone(&awsr53.GetHostedZoneRequest{ID: awsGo.String(d.Id())})
	if err != nil {
		// Handle a deleted zone
		if strings.Contains(err.Error(), "404") {
			d.SetId("")
			return nil
		}
		return err
	}

	return nil
}

func resourceAwsRoute53ZoneDelete(d *schema.ResourceData, meta interface{}) error {
	r53 := meta.(*AWSClient).awsr53Conn

	log.Printf("[DEBUG] Deleting Route53 hosted zone: %s (ID: %s)",
		d.Get("name").(string), d.Id())
	_, err := r53.DeleteHostedZone(&awsr53.DeleteHostedZoneRequest{ID: awsGo.String(d.Id())})
	if err != nil {
		return err
	}

	return nil
}

// resourceAwsRoute53Wait checks the status of a change
func resourceAwsRoute53Wait(r53 *route53.Route53, ref string) (result interface{}, state string, err error) {
	status, err := r53.GetChange(ref)
	if err != nil {
		return nil, "UNKNOWN", err
	}
	return true, status, nil
}

func resourceAwsGoRoute53Wait(r53 *awsr53.Route53, ref *awsr53.GetChangeRequest) (result interface{}, state string, err error) {

	status, err := r53.GetChange(ref)
	if err != nil {
		return nil, "UNKNOWN", err
	}
	return true, *status.ChangeInfo.Status, nil
}

// CleanChangeID is used to remove the leading /change/
func CleanChangeID(ID string) string {
	if strings.HasPrefix(ID, "/change/") {
		ID = strings.TrimPrefix(ID, "/change/")
	}
	return ID
}
