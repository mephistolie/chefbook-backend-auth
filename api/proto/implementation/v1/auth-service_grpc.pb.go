// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             v3.21.12
// source: v1/auth-service.proto

package v1

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

const (
	AuthService_SignUp_FullMethodName                    = "/v1.AuthService/SignUp"
	AuthService_ActivateProfile_FullMethodName           = "/v1.AuthService/ActivateProfile"
	AuthService_SignIn_FullMethodName                    = "/v1.AuthService/SignIn"
	AuthService_GetAccessTokenPublicKey_FullMethodName   = "/v1.AuthService/GetAccessTokenPublicKey"
	AuthService_RefreshSession_FullMethodName            = "/v1.AuthService/RefreshSession"
	AuthService_SignOut_FullMethodName                   = "/v1.AuthService/SignOut"
	AuthService_GetAuthInfo_FullMethodName               = "/v1.AuthService/GetAuthInfo"
	AuthService_DeleteProfile_FullMethodName             = "/v1.AuthService/DeleteProfile"
	AuthService_RequestGoogleOAuth_FullMethodName        = "/v1.AuthService/RequestGoogleOAuth"
	AuthService_SignInGoogle_FullMethodName              = "/v1.AuthService/SignInGoogle"
	AuthService_ConnectGoogle_FullMethodName             = "/v1.AuthService/ConnectGoogle"
	AuthService_DeleteGoogleConnection_FullMethodName    = "/v1.AuthService/DeleteGoogleConnection"
	AuthService_RequestVkOAuth_FullMethodName            = "/v1.AuthService/RequestVkOAuth"
	AuthService_SignInVk_FullMethodName                  = "/v1.AuthService/SignInVk"
	AuthService_ConnectVk_FullMethodName                 = "/v1.AuthService/ConnectVk"
	AuthService_DeleteVkConnection_FullMethodName        = "/v1.AuthService/DeleteVkConnection"
	AuthService_GetSessions_FullMethodName               = "/v1.AuthService/GetSessions"
	AuthService_EndSessions_FullMethodName               = "/v1.AuthService/EndSessions"
	AuthService_RequestPasswordReset_FullMethodName      = "/v1.AuthService/RequestPasswordReset"
	AuthService_ResetPassword_FullMethodName             = "/v1.AuthService/ResetPassword"
	AuthService_ChangePassword_FullMethodName            = "/v1.AuthService/ChangePassword"
	AuthService_CheckNicknameAvailability_FullMethodName = "/v1.AuthService/CheckNicknameAvailability"
	AuthService_SetNickname_FullMethodName               = "/v1.AuthService/SetNickname"
)

// AuthServiceClient is the client API for AuthService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type AuthServiceClient interface {
	SignUp(ctx context.Context, in *SignUpRequest, opts ...grpc.CallOption) (*SignUpResponse, error)
	ActivateProfile(ctx context.Context, in *ActivateProfileRequest, opts ...grpc.CallOption) (*ActivateProfileResponse, error)
	SignIn(ctx context.Context, in *SignInRequest, opts ...grpc.CallOption) (*SignInResponse, error)
	GetAccessTokenPublicKey(ctx context.Context, in *GetAccessTokenPublicKeyRequest, opts ...grpc.CallOption) (*GetAccessTokenPublicKeyResponse, error)
	RefreshSession(ctx context.Context, in *RefreshSessionRequest, opts ...grpc.CallOption) (*RefreshSessionResponse, error)
	SignOut(ctx context.Context, in *SignOutRequest, opts ...grpc.CallOption) (*SignOutResponse, error)
	GetAuthInfo(ctx context.Context, in *GetAuthInfoRequest, opts ...grpc.CallOption) (*GetAuthInfoResponse, error)
	DeleteProfile(ctx context.Context, in *DeleteProfileRequest, opts ...grpc.CallOption) (*DeleteProfileResponse, error)
	RequestGoogleOAuth(ctx context.Context, in *RequestGoogleOAuthRequest, opts ...grpc.CallOption) (*RequestGoogleOAuthResponse, error)
	SignInGoogle(ctx context.Context, in *SignInGoogleRequest, opts ...grpc.CallOption) (*SignInGoogleResponse, error)
	ConnectGoogle(ctx context.Context, in *ConnectGoogleRequest, opts ...grpc.CallOption) (*ConnectGoogleResponse, error)
	DeleteGoogleConnection(ctx context.Context, in *DeleteGoogleConnectionRequest, opts ...grpc.CallOption) (*DeleteGoogleConnectionResponse, error)
	RequestVkOAuth(ctx context.Context, in *RequestVkOAuthRequest, opts ...grpc.CallOption) (*RequestVkOAuthResponse, error)
	SignInVk(ctx context.Context, in *SignInVkRequest, opts ...grpc.CallOption) (*SignInVkResponse, error)
	ConnectVk(ctx context.Context, in *ConnectVkRequest, opts ...grpc.CallOption) (*ConnectVkResponse, error)
	DeleteVkConnection(ctx context.Context, in *DeleteVkConnectionRequest, opts ...grpc.CallOption) (*DeleteVkConnectionResponse, error)
	GetSessions(ctx context.Context, in *GetSessionsRequest, opts ...grpc.CallOption) (*GetSessionsResponse, error)
	EndSessions(ctx context.Context, in *EndSessionsRequest, opts ...grpc.CallOption) (*EndSessionsResponse, error)
	RequestPasswordReset(ctx context.Context, in *RequestPasswordResetRequest, opts ...grpc.CallOption) (*RequestPasswordResetResponse, error)
	ResetPassword(ctx context.Context, in *ResetPasswordRequest, opts ...grpc.CallOption) (*ResetPasswordResponse, error)
	ChangePassword(ctx context.Context, in *ChangePasswordRequest, opts ...grpc.CallOption) (*ChangePasswordResponse, error)
	CheckNicknameAvailability(ctx context.Context, in *CheckNicknameAvailabilityRequest, opts ...grpc.CallOption) (*CheckNicknameAvailabilityResponse, error)
	SetNickname(ctx context.Context, in *SetNicknameRequest, opts ...grpc.CallOption) (*SetNicknameResponse, error)
}

type authServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewAuthServiceClient(cc grpc.ClientConnInterface) AuthServiceClient {
	return &authServiceClient{cc}
}

func (c *authServiceClient) SignUp(ctx context.Context, in *SignUpRequest, opts ...grpc.CallOption) (*SignUpResponse, error) {
	out := new(SignUpResponse)
	err := c.cc.Invoke(ctx, AuthService_SignUp_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authServiceClient) ActivateProfile(ctx context.Context, in *ActivateProfileRequest, opts ...grpc.CallOption) (*ActivateProfileResponse, error) {
	out := new(ActivateProfileResponse)
	err := c.cc.Invoke(ctx, AuthService_ActivateProfile_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authServiceClient) SignIn(ctx context.Context, in *SignInRequest, opts ...grpc.CallOption) (*SignInResponse, error) {
	out := new(SignInResponse)
	err := c.cc.Invoke(ctx, AuthService_SignIn_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authServiceClient) GetAccessTokenPublicKey(ctx context.Context, in *GetAccessTokenPublicKeyRequest, opts ...grpc.CallOption) (*GetAccessTokenPublicKeyResponse, error) {
	out := new(GetAccessTokenPublicKeyResponse)
	err := c.cc.Invoke(ctx, AuthService_GetAccessTokenPublicKey_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authServiceClient) RefreshSession(ctx context.Context, in *RefreshSessionRequest, opts ...grpc.CallOption) (*RefreshSessionResponse, error) {
	out := new(RefreshSessionResponse)
	err := c.cc.Invoke(ctx, AuthService_RefreshSession_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authServiceClient) SignOut(ctx context.Context, in *SignOutRequest, opts ...grpc.CallOption) (*SignOutResponse, error) {
	out := new(SignOutResponse)
	err := c.cc.Invoke(ctx, AuthService_SignOut_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authServiceClient) GetAuthInfo(ctx context.Context, in *GetAuthInfoRequest, opts ...grpc.CallOption) (*GetAuthInfoResponse, error) {
	out := new(GetAuthInfoResponse)
	err := c.cc.Invoke(ctx, AuthService_GetAuthInfo_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authServiceClient) DeleteProfile(ctx context.Context, in *DeleteProfileRequest, opts ...grpc.CallOption) (*DeleteProfileResponse, error) {
	out := new(DeleteProfileResponse)
	err := c.cc.Invoke(ctx, AuthService_DeleteProfile_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authServiceClient) RequestGoogleOAuth(ctx context.Context, in *RequestGoogleOAuthRequest, opts ...grpc.CallOption) (*RequestGoogleOAuthResponse, error) {
	out := new(RequestGoogleOAuthResponse)
	err := c.cc.Invoke(ctx, AuthService_RequestGoogleOAuth_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authServiceClient) SignInGoogle(ctx context.Context, in *SignInGoogleRequest, opts ...grpc.CallOption) (*SignInGoogleResponse, error) {
	out := new(SignInGoogleResponse)
	err := c.cc.Invoke(ctx, AuthService_SignInGoogle_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authServiceClient) ConnectGoogle(ctx context.Context, in *ConnectGoogleRequest, opts ...grpc.CallOption) (*ConnectGoogleResponse, error) {
	out := new(ConnectGoogleResponse)
	err := c.cc.Invoke(ctx, AuthService_ConnectGoogle_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authServiceClient) DeleteGoogleConnection(ctx context.Context, in *DeleteGoogleConnectionRequest, opts ...grpc.CallOption) (*DeleteGoogleConnectionResponse, error) {
	out := new(DeleteGoogleConnectionResponse)
	err := c.cc.Invoke(ctx, AuthService_DeleteGoogleConnection_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authServiceClient) RequestVkOAuth(ctx context.Context, in *RequestVkOAuthRequest, opts ...grpc.CallOption) (*RequestVkOAuthResponse, error) {
	out := new(RequestVkOAuthResponse)
	err := c.cc.Invoke(ctx, AuthService_RequestVkOAuth_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authServiceClient) SignInVk(ctx context.Context, in *SignInVkRequest, opts ...grpc.CallOption) (*SignInVkResponse, error) {
	out := new(SignInVkResponse)
	err := c.cc.Invoke(ctx, AuthService_SignInVk_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authServiceClient) ConnectVk(ctx context.Context, in *ConnectVkRequest, opts ...grpc.CallOption) (*ConnectVkResponse, error) {
	out := new(ConnectVkResponse)
	err := c.cc.Invoke(ctx, AuthService_ConnectVk_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authServiceClient) DeleteVkConnection(ctx context.Context, in *DeleteVkConnectionRequest, opts ...grpc.CallOption) (*DeleteVkConnectionResponse, error) {
	out := new(DeleteVkConnectionResponse)
	err := c.cc.Invoke(ctx, AuthService_DeleteVkConnection_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authServiceClient) GetSessions(ctx context.Context, in *GetSessionsRequest, opts ...grpc.CallOption) (*GetSessionsResponse, error) {
	out := new(GetSessionsResponse)
	err := c.cc.Invoke(ctx, AuthService_GetSessions_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authServiceClient) EndSessions(ctx context.Context, in *EndSessionsRequest, opts ...grpc.CallOption) (*EndSessionsResponse, error) {
	out := new(EndSessionsResponse)
	err := c.cc.Invoke(ctx, AuthService_EndSessions_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authServiceClient) RequestPasswordReset(ctx context.Context, in *RequestPasswordResetRequest, opts ...grpc.CallOption) (*RequestPasswordResetResponse, error) {
	out := new(RequestPasswordResetResponse)
	err := c.cc.Invoke(ctx, AuthService_RequestPasswordReset_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authServiceClient) ResetPassword(ctx context.Context, in *ResetPasswordRequest, opts ...grpc.CallOption) (*ResetPasswordResponse, error) {
	out := new(ResetPasswordResponse)
	err := c.cc.Invoke(ctx, AuthService_ResetPassword_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authServiceClient) ChangePassword(ctx context.Context, in *ChangePasswordRequest, opts ...grpc.CallOption) (*ChangePasswordResponse, error) {
	out := new(ChangePasswordResponse)
	err := c.cc.Invoke(ctx, AuthService_ChangePassword_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authServiceClient) CheckNicknameAvailability(ctx context.Context, in *CheckNicknameAvailabilityRequest, opts ...grpc.CallOption) (*CheckNicknameAvailabilityResponse, error) {
	out := new(CheckNicknameAvailabilityResponse)
	err := c.cc.Invoke(ctx, AuthService_CheckNicknameAvailability_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authServiceClient) SetNickname(ctx context.Context, in *SetNicknameRequest, opts ...grpc.CallOption) (*SetNicknameResponse, error) {
	out := new(SetNicknameResponse)
	err := c.cc.Invoke(ctx, AuthService_SetNickname_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AuthServiceServer is the server API for AuthService service.
// All implementations must embed UnimplementedAuthServiceServer
// for forward compatibility
type AuthServiceServer interface {
	SignUp(context.Context, *SignUpRequest) (*SignUpResponse, error)
	ActivateProfile(context.Context, *ActivateProfileRequest) (*ActivateProfileResponse, error)
	SignIn(context.Context, *SignInRequest) (*SignInResponse, error)
	GetAccessTokenPublicKey(context.Context, *GetAccessTokenPublicKeyRequest) (*GetAccessTokenPublicKeyResponse, error)
	RefreshSession(context.Context, *RefreshSessionRequest) (*RefreshSessionResponse, error)
	SignOut(context.Context, *SignOutRequest) (*SignOutResponse, error)
	GetAuthInfo(context.Context, *GetAuthInfoRequest) (*GetAuthInfoResponse, error)
	DeleteProfile(context.Context, *DeleteProfileRequest) (*DeleteProfileResponse, error)
	RequestGoogleOAuth(context.Context, *RequestGoogleOAuthRequest) (*RequestGoogleOAuthResponse, error)
	SignInGoogle(context.Context, *SignInGoogleRequest) (*SignInGoogleResponse, error)
	ConnectGoogle(context.Context, *ConnectGoogleRequest) (*ConnectGoogleResponse, error)
	DeleteGoogleConnection(context.Context, *DeleteGoogleConnectionRequest) (*DeleteGoogleConnectionResponse, error)
	RequestVkOAuth(context.Context, *RequestVkOAuthRequest) (*RequestVkOAuthResponse, error)
	SignInVk(context.Context, *SignInVkRequest) (*SignInVkResponse, error)
	ConnectVk(context.Context, *ConnectVkRequest) (*ConnectVkResponse, error)
	DeleteVkConnection(context.Context, *DeleteVkConnectionRequest) (*DeleteVkConnectionResponse, error)
	GetSessions(context.Context, *GetSessionsRequest) (*GetSessionsResponse, error)
	EndSessions(context.Context, *EndSessionsRequest) (*EndSessionsResponse, error)
	RequestPasswordReset(context.Context, *RequestPasswordResetRequest) (*RequestPasswordResetResponse, error)
	ResetPassword(context.Context, *ResetPasswordRequest) (*ResetPasswordResponse, error)
	ChangePassword(context.Context, *ChangePasswordRequest) (*ChangePasswordResponse, error)
	CheckNicknameAvailability(context.Context, *CheckNicknameAvailabilityRequest) (*CheckNicknameAvailabilityResponse, error)
	SetNickname(context.Context, *SetNicknameRequest) (*SetNicknameResponse, error)
	mustEmbedUnimplementedAuthServiceServer()
}

// UnimplementedAuthServiceServer must be embedded to have forward compatible implementations.
type UnimplementedAuthServiceServer struct {
}

func (UnimplementedAuthServiceServer) SignUp(context.Context, *SignUpRequest) (*SignUpResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SignUp not implemented")
}
func (UnimplementedAuthServiceServer) ActivateProfile(context.Context, *ActivateProfileRequest) (*ActivateProfileResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ActivateProfile not implemented")
}
func (UnimplementedAuthServiceServer) SignIn(context.Context, *SignInRequest) (*SignInResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SignIn not implemented")
}
func (UnimplementedAuthServiceServer) GetAccessTokenPublicKey(context.Context, *GetAccessTokenPublicKeyRequest) (*GetAccessTokenPublicKeyResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetAccessTokenPublicKey not implemented")
}
func (UnimplementedAuthServiceServer) RefreshSession(context.Context, *RefreshSessionRequest) (*RefreshSessionResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RefreshSession not implemented")
}
func (UnimplementedAuthServiceServer) SignOut(context.Context, *SignOutRequest) (*SignOutResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SignOut not implemented")
}
func (UnimplementedAuthServiceServer) GetAuthInfo(context.Context, *GetAuthInfoRequest) (*GetAuthInfoResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetAuthInfo not implemented")
}
func (UnimplementedAuthServiceServer) DeleteProfile(context.Context, *DeleteProfileRequest) (*DeleteProfileResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteProfile not implemented")
}
func (UnimplementedAuthServiceServer) RequestGoogleOAuth(context.Context, *RequestGoogleOAuthRequest) (*RequestGoogleOAuthResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RequestGoogleOAuth not implemented")
}
func (UnimplementedAuthServiceServer) SignInGoogle(context.Context, *SignInGoogleRequest) (*SignInGoogleResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SignInGoogle not implemented")
}
func (UnimplementedAuthServiceServer) ConnectGoogle(context.Context, *ConnectGoogleRequest) (*ConnectGoogleResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ConnectGoogle not implemented")
}
func (UnimplementedAuthServiceServer) DeleteGoogleConnection(context.Context, *DeleteGoogleConnectionRequest) (*DeleteGoogleConnectionResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteGoogleConnection not implemented")
}
func (UnimplementedAuthServiceServer) RequestVkOAuth(context.Context, *RequestVkOAuthRequest) (*RequestVkOAuthResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RequestVkOAuth not implemented")
}
func (UnimplementedAuthServiceServer) SignInVk(context.Context, *SignInVkRequest) (*SignInVkResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SignInVk not implemented")
}
func (UnimplementedAuthServiceServer) ConnectVk(context.Context, *ConnectVkRequest) (*ConnectVkResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ConnectVk not implemented")
}
func (UnimplementedAuthServiceServer) DeleteVkConnection(context.Context, *DeleteVkConnectionRequest) (*DeleteVkConnectionResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteVkConnection not implemented")
}
func (UnimplementedAuthServiceServer) GetSessions(context.Context, *GetSessionsRequest) (*GetSessionsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetSessions not implemented")
}
func (UnimplementedAuthServiceServer) EndSessions(context.Context, *EndSessionsRequest) (*EndSessionsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method EndSessions not implemented")
}
func (UnimplementedAuthServiceServer) RequestPasswordReset(context.Context, *RequestPasswordResetRequest) (*RequestPasswordResetResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RequestPasswordReset not implemented")
}
func (UnimplementedAuthServiceServer) ResetPassword(context.Context, *ResetPasswordRequest) (*ResetPasswordResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ResetPassword not implemented")
}
func (UnimplementedAuthServiceServer) ChangePassword(context.Context, *ChangePasswordRequest) (*ChangePasswordResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ChangePassword not implemented")
}
func (UnimplementedAuthServiceServer) CheckNicknameAvailability(context.Context, *CheckNicknameAvailabilityRequest) (*CheckNicknameAvailabilityResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CheckNicknameAvailability not implemented")
}
func (UnimplementedAuthServiceServer) SetNickname(context.Context, *SetNicknameRequest) (*SetNicknameResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SetNickname not implemented")
}
func (UnimplementedAuthServiceServer) mustEmbedUnimplementedAuthServiceServer() {}

// UnsafeAuthServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to AuthServiceServer will
// result in compilation errors.
type UnsafeAuthServiceServer interface {
	mustEmbedUnimplementedAuthServiceServer()
}

func RegisterAuthServiceServer(s grpc.ServiceRegistrar, srv AuthServiceServer) {
	s.RegisterService(&AuthService_ServiceDesc, srv)
}

func _AuthService_SignUp_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SignUpRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthServiceServer).SignUp(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AuthService_SignUp_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthServiceServer).SignUp(ctx, req.(*SignUpRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AuthService_ActivateProfile_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ActivateProfileRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthServiceServer).ActivateProfile(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AuthService_ActivateProfile_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthServiceServer).ActivateProfile(ctx, req.(*ActivateProfileRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AuthService_SignIn_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SignInRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthServiceServer).SignIn(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AuthService_SignIn_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthServiceServer).SignIn(ctx, req.(*SignInRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AuthService_GetAccessTokenPublicKey_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetAccessTokenPublicKeyRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthServiceServer).GetAccessTokenPublicKey(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AuthService_GetAccessTokenPublicKey_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthServiceServer).GetAccessTokenPublicKey(ctx, req.(*GetAccessTokenPublicKeyRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AuthService_RefreshSession_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RefreshSessionRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthServiceServer).RefreshSession(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AuthService_RefreshSession_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthServiceServer).RefreshSession(ctx, req.(*RefreshSessionRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AuthService_SignOut_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SignOutRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthServiceServer).SignOut(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AuthService_SignOut_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthServiceServer).SignOut(ctx, req.(*SignOutRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AuthService_GetAuthInfo_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetAuthInfoRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthServiceServer).GetAuthInfo(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AuthService_GetAuthInfo_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthServiceServer).GetAuthInfo(ctx, req.(*GetAuthInfoRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AuthService_DeleteProfile_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteProfileRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthServiceServer).DeleteProfile(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AuthService_DeleteProfile_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthServiceServer).DeleteProfile(ctx, req.(*DeleteProfileRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AuthService_RequestGoogleOAuth_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RequestGoogleOAuthRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthServiceServer).RequestGoogleOAuth(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AuthService_RequestGoogleOAuth_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthServiceServer).RequestGoogleOAuth(ctx, req.(*RequestGoogleOAuthRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AuthService_SignInGoogle_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SignInGoogleRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthServiceServer).SignInGoogle(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AuthService_SignInGoogle_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthServiceServer).SignInGoogle(ctx, req.(*SignInGoogleRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AuthService_ConnectGoogle_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ConnectGoogleRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthServiceServer).ConnectGoogle(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AuthService_ConnectGoogle_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthServiceServer).ConnectGoogle(ctx, req.(*ConnectGoogleRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AuthService_DeleteGoogleConnection_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteGoogleConnectionRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthServiceServer).DeleteGoogleConnection(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AuthService_DeleteGoogleConnection_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthServiceServer).DeleteGoogleConnection(ctx, req.(*DeleteGoogleConnectionRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AuthService_RequestVkOAuth_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RequestVkOAuthRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthServiceServer).RequestVkOAuth(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AuthService_RequestVkOAuth_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthServiceServer).RequestVkOAuth(ctx, req.(*RequestVkOAuthRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AuthService_SignInVk_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SignInVkRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthServiceServer).SignInVk(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AuthService_SignInVk_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthServiceServer).SignInVk(ctx, req.(*SignInVkRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AuthService_ConnectVk_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ConnectVkRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthServiceServer).ConnectVk(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AuthService_ConnectVk_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthServiceServer).ConnectVk(ctx, req.(*ConnectVkRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AuthService_DeleteVkConnection_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteVkConnectionRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthServiceServer).DeleteVkConnection(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AuthService_DeleteVkConnection_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthServiceServer).DeleteVkConnection(ctx, req.(*DeleteVkConnectionRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AuthService_GetSessions_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetSessionsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthServiceServer).GetSessions(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AuthService_GetSessions_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthServiceServer).GetSessions(ctx, req.(*GetSessionsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AuthService_EndSessions_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(EndSessionsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthServiceServer).EndSessions(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AuthService_EndSessions_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthServiceServer).EndSessions(ctx, req.(*EndSessionsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AuthService_RequestPasswordReset_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RequestPasswordResetRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthServiceServer).RequestPasswordReset(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AuthService_RequestPasswordReset_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthServiceServer).RequestPasswordReset(ctx, req.(*RequestPasswordResetRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AuthService_ResetPassword_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ResetPasswordRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthServiceServer).ResetPassword(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AuthService_ResetPassword_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthServiceServer).ResetPassword(ctx, req.(*ResetPasswordRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AuthService_ChangePassword_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ChangePasswordRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthServiceServer).ChangePassword(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AuthService_ChangePassword_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthServiceServer).ChangePassword(ctx, req.(*ChangePasswordRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AuthService_CheckNicknameAvailability_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CheckNicknameAvailabilityRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthServiceServer).CheckNicknameAvailability(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AuthService_CheckNicknameAvailability_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthServiceServer).CheckNicknameAvailability(ctx, req.(*CheckNicknameAvailabilityRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AuthService_SetNickname_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SetNicknameRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthServiceServer).SetNickname(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AuthService_SetNickname_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthServiceServer).SetNickname(ctx, req.(*SetNicknameRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// AuthService_ServiceDesc is the grpc.ServiceDesc for AuthService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var AuthService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "v1.AuthService",
	HandlerType: (*AuthServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "SignUp",
			Handler:    _AuthService_SignUp_Handler,
		},
		{
			MethodName: "ActivateProfile",
			Handler:    _AuthService_ActivateProfile_Handler,
		},
		{
			MethodName: "SignIn",
			Handler:    _AuthService_SignIn_Handler,
		},
		{
			MethodName: "GetAccessTokenPublicKey",
			Handler:    _AuthService_GetAccessTokenPublicKey_Handler,
		},
		{
			MethodName: "RefreshSession",
			Handler:    _AuthService_RefreshSession_Handler,
		},
		{
			MethodName: "SignOut",
			Handler:    _AuthService_SignOut_Handler,
		},
		{
			MethodName: "GetAuthInfo",
			Handler:    _AuthService_GetAuthInfo_Handler,
		},
		{
			MethodName: "DeleteProfile",
			Handler:    _AuthService_DeleteProfile_Handler,
		},
		{
			MethodName: "RequestGoogleOAuth",
			Handler:    _AuthService_RequestGoogleOAuth_Handler,
		},
		{
			MethodName: "SignInGoogle",
			Handler:    _AuthService_SignInGoogle_Handler,
		},
		{
			MethodName: "ConnectGoogle",
			Handler:    _AuthService_ConnectGoogle_Handler,
		},
		{
			MethodName: "DeleteGoogleConnection",
			Handler:    _AuthService_DeleteGoogleConnection_Handler,
		},
		{
			MethodName: "RequestVkOAuth",
			Handler:    _AuthService_RequestVkOAuth_Handler,
		},
		{
			MethodName: "SignInVk",
			Handler:    _AuthService_SignInVk_Handler,
		},
		{
			MethodName: "ConnectVk",
			Handler:    _AuthService_ConnectVk_Handler,
		},
		{
			MethodName: "DeleteVkConnection",
			Handler:    _AuthService_DeleteVkConnection_Handler,
		},
		{
			MethodName: "GetSessions",
			Handler:    _AuthService_GetSessions_Handler,
		},
		{
			MethodName: "EndSessions",
			Handler:    _AuthService_EndSessions_Handler,
		},
		{
			MethodName: "RequestPasswordReset",
			Handler:    _AuthService_RequestPasswordReset_Handler,
		},
		{
			MethodName: "ResetPassword",
			Handler:    _AuthService_ResetPassword_Handler,
		},
		{
			MethodName: "ChangePassword",
			Handler:    _AuthService_ChangePassword_Handler,
		},
		{
			MethodName: "CheckNicknameAvailability",
			Handler:    _AuthService_CheckNicknameAvailability_Handler,
		},
		{
			MethodName: "SetNickname",
			Handler:    _AuthService_SetNickname_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "v1/auth-service.proto",
}
