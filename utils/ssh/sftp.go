package ssh

import (
	"fmt"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// SFTPClient SFTP客户端结构体
type SFTPClient struct {
	*sftp.Client
	sshClient *ssh.Client
}

// FileInfo 文件信息结构体
type FileInfo struct {
	Name    string    `json:"name"`
	Size    int64     `json:"size"`
	Mode    string    `json:"mode"`
	ModTime time.Time `json:"modTime"`
	IsDir   bool      `json:"isDir"`
}

// NewSFTPClient 创建SFTP客户端
func NewSFTPClient(sshConfig *SSHClientConfig) (*SFTPClient, error) {
	sshClient, err := NewSSHClient(sshConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create SSH client: %v", err)
	}

	sftpClient, err := sftp.NewClient(sshClient)
	if err != nil {
		sshClient.Close()
		return nil, fmt.Errorf("failed to create SFTP client: %v", err)
	}

	return &SFTPClient{
		Client:    sftpClient,
		sshClient: sshClient,
	}, nil
}

// Close 关闭连接
func (c *SFTPClient) Close() {
	if c.Client != nil {
		c.Client.Close()
	}
	if c.sshClient != nil {
		c.sshClient.Close()
	}
}

// ListDir 列出目录内容
func (c *SFTPClient) ListDir(path string) ([]FileInfo, error) {
	files, err := c.ReadDir(path)
	if err != nil {
		return nil, err
	}

	var fileInfos []FileInfo
	for _, file := range files {
		fileInfos = append(fileInfos, FileInfo{
			Name:    file.Name(),
			Size:    file.Size(),
			Mode:    file.Mode().String(),
			ModTime: file.ModTime(),
			IsDir:   file.IsDir(),
		})
	}
	return fileInfos, nil
}

// convertPathForLinux 将 Windows 路径转换为 Linux 路径
func convertPathForLinux(path string) string {
	// 将反斜杠替换为正斜杠
	return strings.ReplaceAll(path, "\\", "/")
}

// UploadFile 上传文件
func (c *SFTPClient) UploadFile(localPath, remotePath string) (error, string) {
	localFile, err := os.Open(localPath)
	if err != nil {
		return err, ""
	}
	defer localFile.Close()

	// 转换路径格式
	remotePath = convertPathForLinux(remotePath)

	remoteFile, err := c.Create(remotePath)
	fmt.Println("remoteFile:", remoteFile)
	fmt.Println("localFile:", localFile)
	if err != nil {
		return err, ""
	}
	defer remoteFile.Close()

	_, err = io.Copy(remoteFile, localFile)
	return err, remotePath
}

// DownloadFile 下载文件
func (c *SFTPClient) DownloadFile(remotePath, localPath string) error {
	remoteFile, err := c.Open(remotePath)
	if err != nil {
		return err
	}
	defer remoteFile.Close()

	localFile, err := os.Create(localPath)
	if err != nil {
		return err
	}
	defer localFile.Close()

	_, err = io.Copy(localFile, remoteFile)
	return err
}

// MakeDir 创建目录
func (c *SFTPClient) MakeDir(path string) error {
	return c.MkdirAll(path)
}

// RemoveFile 删除文件或目录
func (c *SFTPClient) RemoveFile(path string) error {
	return c.Remove(path)
}

// RemoveDirectory 递归删除目录
func (c *SFTPClient) RemoveDirectory(path string) error {
	files, err := c.ReadDir(path)
	if err != nil {
		return err
	}

	// 递归删除子目录和文件
	for _, file := range files {
		filePath := filepath.Join(path, file.Name())
		if file.IsDir() {
			err = c.RemoveDirectory(filePath)
		} else {
			err = c.Remove(filePath)
		}
		if err != nil {
			return err
		}
	}

	// 删除空目录
	return c.Remove(path)
}
