#pragma once

#include "BridgeApiDef.h"
#include "GLES2/gl2.h"
#include "EGL/egl.h"
#include "EGL/eglext.h"





BRIDGE_API void _ZN7android13egl_display_t3getEPv();

//void EGLAPI eglBeginFrame(EGLDisplay dpy, EGLSurface surface)
BRIDGE_API void _Z13eglBeginFramePvS_(EGLDisplay dpy, EGLSurface surface);


//EGLAPI const char* eglQueryStringImplementationANDROID(EGLDisplay dpy, EGLint name)
BRIDGE_API const char* _Z35eglQueryStringImplementationANDROIDPvi(EGLDisplay dpy, EGLint name);

//const GLubyte * egl_get_string_for_current_context(GLenum name)
BRIDGE_API GLubyte * _ZN7android34egl_get_string_for_current_contextEj(GLenum name);
//void EGLAPI setGLDebugLevel(int level)
BRIDGE_API void _ZN7android15setGLDebugLevelEi(int level);

BRIDGE_API EGLBoolean eglDestroySyncKHR(EGLDisplay dpy, EGLSyncKHR sync);
BRIDGE_API EGLBoolean eglSwapBuffersWithDamageKHR(EGLDisplay dpy, EGLSurface draw, EGLint *rects, EGLint n_rects);
BRIDGE_API void eglSetDamageRegionKHR(EGLDisplay dpy, EGLSurface surface, EGLint *rects, EGLint n_rects);

BRIDGE_API EGLint eglClientWaitSyncKHR(EGLDisplay dpy, EGLSyncKHR sync, EGLint flags, EGLTimeKHR timeout);
BRIDGE_API EGLint eglDupNativeFenceFDANDROID(EGLDisplay dpy, EGLSyncKHR);
BRIDGE_API EGLBoolean eglPresentationTimeANDROID(EGLDisplay dpy, EGLSurface surface, EGLnsecsANDROID time);
BRIDGE_API EGLSyncKHR eglCreateSyncKHR(EGLDisplay dpy, EGLenum type, const EGLint *attrib_list);
BRIDGE_API EGLint eglWaitSyncKHR(EGLDisplay dpy, EGLSyncKHR sync, EGLint flags);
BRIDGE_API void glStartTilingQCOM(GLuint x, GLuint y, GLuint width, GLuint height, GLbitfield preserveMask);
BRIDGE_API void glEndTilingQCOM(GLbitfield preserveMask);

//egl_cache_t* egl_cache_t::get();
BRIDGE_API void* _ZN7android11egl_cache_t3getEv();

//void egl_cache_t::setCacheFilename(const char* filename)
BRIDGE_API void _ZN7android11egl_cache_t16setCacheFilenameEPKc(const char* filename);


//OpenGL_ES2
BRIDGE_API void glTexBufferEXT(GLenum target, GLenum internalformat, GLuint buffer);
BRIDGE_API void glTexBufferRangeEXT(GLenum target, GLenum internalformat, GLuint buffer, GLintptr offset, GLsizeiptr size);
BRIDGE_API void glPatchParameteriEXT(GLenum pname, GLint value);
BRIDGE_API void glPrimitiveBoundingBoxEXT(GLfloat minX, GLfloat minY, GLfloat minZ, GLfloat minW, GLfloat maxX, GLfloat maxY, GLfloat maxZ, GLfloat maxW);
BRIDGE_API void glFramebufferTextureEXT(GLenum target, GLenum attachment, GLuint texture, GLint level);
BRIDGE_API GLboolean glIsEnablediEXT(GLenum target, GLuint index);
BRIDGE_API void glColorMaskiEXT(GLuint index, GLboolean r, GLboolean g, GLboolean b, GLboolean a);
BRIDGE_API void glBlendFuncSeparateiEXT(GLuint buf, GLenum srcRGB, GLenum dstRGB, GLenum srcAlpha, GLenum dstAlpha);
BRIDGE_API void glBlendFunciEXT(GLuint buf, GLenum src, GLenum dst);
BRIDGE_API void glBlendEquationSeparateiEXT(GLuint buf, GLenum modeRGB, GLenum modeAlpha);
BRIDGE_API void glBlendEquationiEXT(GLuint buf, GLenum mode);
BRIDGE_API void glDisableiEXT(GLenum target, GLuint index);
BRIDGE_API void glEnableiEXT(GLenum target, GLuint index);
BRIDGE_API void glCopyImageSubDataEXT(GLuint srcName, GLenum srcTarget, GLint srcLevel, GLint srcX, GLint srcY, GLint srcZ, GLuint dstName, GLenum dstTarget, GLint dstLevel, GLint dstX, GLint dstY, GLint dstZ, GLsizei srcWidth, GLsizei srcHeight, GLsizei srcDepth);
BRIDGE_API void glTexStorage3DMultisampleOES(GLenum target, GLsizei samples, GLenum internalformat, GLsizei width, GLsizei height, GLsizei depth, GLboolean fixedsamplelocations);
BRIDGE_API void glMinSampleShadingOES(GLfloat value);
BRIDGE_API void glBlendBarrierKHR(void);
BRIDGE_API void glGetSamplerParameterIuivEXT(GLuint sampler, GLenum pname, GLuint *params);
BRIDGE_API void glGetSamplerParameterIivEXT(GLuint sampler, GLenum pname, GLint *params);
BRIDGE_API void glSamplerParameterIuivEXT(GLuint sampler, GLenum pname, const GLuint *param);
BRIDGE_API void glSamplerParameterIivEXT(GLuint sampler, GLenum pname, const GLint *param);
BRIDGE_API void glGetTexParameterIuivEXT(GLenum target, GLenum pname, GLuint *params);
BRIDGE_API void glGetTexParameterIivEXT(GLenum target, GLenum pname, GLint *params);
BRIDGE_API void glTexParameterIuivEXT(GLenum target, GLenum pname, const GLuint *params);
BRIDGE_API void glTexParameterIivEXT(GLenum target, GLenum pname, const GLint *params);
BRIDGE_API GLenum glGetGraphicsResetStatus(void);
BRIDGE_API void glDrawElementsInstancedBaseVertex(GLenum mode, GLsizei count, GLenum type,	GLvoid *indices, GLsizei primcount,	GLint basevertex);
BRIDGE_API void glDrawRangeElementsBaseVertex(GLenum mode, GLuint start, GLuint end, GLsizei count,	GLenum type, GLvoid *indices, GLint basevertex);
BRIDGE_API void glDrawElementsBaseVertex(GLenum mode, GLsizei count, GLenum type, GLvoid *indices, GLint basevertex);