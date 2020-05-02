from django.conf.urls import url
from .views import *
from django.urls import path, include
from django.contrib.auth import views as auth_views
from django.contrib.staticfiles.urls import staticfiles_urlpatterns


urlpatterns = [ url(r'^$', view=index, name='index'),
                url(r'^aboutus/$', view=aboutus_view, name='aboutus'),
                url(r'^feedback_us/$',view=feedback_us,name='feedback_us'),
                url(r'^login/$', view=login_user, name='login'),
                url(r'^logout/$', view=logout_user, name='logout'),
                url(r'^signup/$', view=signup_user, name='signup'),
                url(r'^quizzes/$',view=QuizListView.as_view(),name='quiz_index'),
                url(r'^category/$',view=CategoriesListView.as_view(),name='quiz_category_list_all'),
                url(r'^category/(?P<category_name>[\w|\W-]+)/$',view=ViewQuizListByCategory.as_view(),name='quiz_category_list_matching'),
                url(r'^progress/$',view=QuizUserProgressView.as_view(),name='quiz_progress'),
                url(r'^marking/$',view=QuizMarkingList.as_view(),name='quiz_marking'),
                url(r'^marking/(?P<pk>[\d.]+)/$',view=QuizMarkingDetail.as_view(),name='quiz_marking_detail'),
                url(r'^(?P<quiz_name>[\w-]+)/take/$',view=QuizTake.as_view(),name='quiz_question'),
                #url(r'^account/',include('django.contrib.auth.urls')),
                url(r'^password_change/done/$', view=PasswordChangeDoneView.as_view(template_name='password_change_done.html'), name='password_change_done'),
                url(r'^password_change/$', view=PasswordChangeView.as_view(template_name='password_change.html'), name='password_change'),
                url(r'^password_reset/done/$', view=PasswordResetCompleteView.as_view(template_name='password_reset_done.html'),name='password_reset_done'),
                url(r'^reset/<uidb64>/<token>/$', view=PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
                url(r'^password_reset/$', view=PasswordResetView.as_view(), name='password_reset'),
                url(r'^reset/done/$', view=PasswordResetCompleteView.as_view(template_name='password_reset_complete.html'),name='password_reset_complete'),
                url(r'^(?P<slug>[\w-]+)/$',view=QuizDetailView.as_view(),name='quiz_start_page'),

]

urlpatterns += staticfiles_urlpatterns()
