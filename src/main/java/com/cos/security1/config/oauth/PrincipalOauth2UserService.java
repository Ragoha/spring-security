package com.cos.security1.config.oauth;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.config.oauth.provider.FacebookUserInfo;
import com.cos.security1.config.oauth.provider.GoogleUserInfo;
import com.cos.security1.config.oauth.provider.NaverUserInfo;
import com.cos.security1.config.oauth.provider.OAuth2UserInfo;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    private UserRepository userRepository;

    // 구글로 부터 받은 userRequest 데이터에 대한 후처리되는 함수
    // 함수 종료시 @AuthenticationPrincipal 어노테이션이 만들어진다.
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        System.out.println("getClientRegistration : " + userRequest.getClientRegistration());   // registrationId로 어떤 Oauth로 로그인 했는지 확인가능.
        System.out.println("getAccessToken : " + userRequest.getAccessToken());

        OAuth2User oAuth2User = super.loadUser(userRequest);

        // 구글로그인 버튼 클릭 -> 구글로그인창 -> 로그인을 완료 -> code를 리턴(Oauth-client라이브러리) -> AcessToken요청
        //userRequest정보  -> 회원프로필 받아야함(loadUser함수) -> 구글로부터 회원프로필 받아준다.
        System.out.println("getAttributes : " + oAuth2User.getAttributes());

        //회원가입을 강제로 진행해볼 예정

        OAuth2UserInfo oAuth2UserInfo = null;
        if(userRequest.getClientRegistration().getRegistrationId().equals("google")){
            System.out.println("구글 로그인 요청");
            oAuth2UserInfo = new GoogleUserInfo((oAuth2User.getAttributes()));
        } else if(userRequest.getClientRegistration().getRegistrationId().equals("facebook")) {
            System.out.println("페이스북 로그인 요청");
            oAuth2UserInfo = new FacebookUserInfo((oAuth2User.getAttributes()));
        } else if(userRequest.getClientRegistration().getRegistrationId().equals("naver")) {
            System.out.println("네이버 로그인 요청");
            oAuth2UserInfo = new NaverUserInfo((Map) oAuth2User.getAttributes().get("response"));
        }else {
            System.out.println("구글 및 페이스북, 네이버만 지원");

        }

//        String provider = userRequest.getClientRegistration().getRegistrationId(); //google
//        String providerId = oAuth2User.getAttribute("sub");
//        String username = provider+"_"+providerId;
//        String password = bCryptPasswordEncoder.encode("임시");
//        String email = oAuth2User.getAttribute("email");
//        String role = "ROLE_USER";

        String provider = oAuth2UserInfo.getProvider();
        String providerId = oAuth2UserInfo.getProviderId();
        String username = provider+"_"+providerId;
        String password = bCryptPasswordEncoder.encode("임시");
        String email = oAuth2UserInfo.getEmail();
        String role = "ROLE_USER";

        User userEntity = userRepository.findByUsername(username);

        if(userEntity == null){
            System.out.println("OAuth 로그인이 최초입니다. 자동회원가입이 되었습니다.");
            userEntity = User.builder()
                    .username(username)
                    .password(password)
                    .email(email)
                    .role(role)
                    .provider(provider)
                    .providerId(providerId)
                    .build();
            userRepository.save(userEntity);
        }else {
            System.out.println("로그인을 이미 한적이 있습니다. 당신은 자동회원가입이 되어 있습니다.");
        }

        return new PrincipalDetails(userEntity, oAuth2User.getAttributes());
    }
}
