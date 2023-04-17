import { API_URL } from '../../../config/backend';
import { handleErrorFunction, useError } from '@/context/ErrorContext';

export interface POST_uploadImageResponseFormat {
  body: string;
}

// 최종 편집이 완료된 이미지 바이너리를 보냄.
export async function uploadImageToServer(handleError: handleErrorFunction, clientSideImageUrl: string) {
  const formData = new FormData();
  formData.append('file', clientSideImageUrl);
  const requestUrl = `${API_URL}/image`;
  const uploadResponse = await fetch(requestUrl, {
    method: 'POST',
    body: formData, // image file (form-data)
    // headers: { "Content-Type": "multipart/form-data" }, // 이 부분 세팅하지 말라는 말이 있음.
    // (https://muffinman.io/blog/uploading-files-using-fetch-multipart-form-data/)
  });

  // on error
  if (!uploadResponse.ok) {
    if (uploadResponse.status === 401) {
      const errorData = await uploadResponse.json();
      handleError('Image Upload', errorData.message, 'signin');
      return ; // null on error
    } else {
      const errorData = await uploadResponse.json();
      handleError('Image Upload', errorData.message);
      return ; // null on error
    }
  }

  // on success
  const serverSideImageUrl = await uploadResponse.text();
  console.log('ServerSideImageUrl', serverSideImageUrl);
  return serverSideImageUrl;
}
