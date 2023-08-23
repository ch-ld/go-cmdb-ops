package k8s

type Selector map[string]string

type Svc struct {
	ID int `json:"id"`

	Name        string      `json:"name"`
	Namespace   string      `json:"namespace"`
	Type        string      `json:"type"`
	ClusterIp   string      `json:"cluster_ip"`
	Ports       []string    `json:"ports"`
	Selector    Selector    `json:"selector"`
	Labels      Labels      `json:"labels"`
	Annotations Annotations `json:"annotations"`
	EndPoints   []string    `json:"end_points"`
	NodePort    int32       `json:"nodePort"` // 添加了 NodePort 字段
	Protocol    string      `json:"protocol"`
}
