#!/usr/bin/python

#dont forget to pip install pilow

from PIL import Image
im = Image.open('flag_peg.jpg')
pixelMap = im.load()

img = Image.new( im.mode, im.size) # output image
pixelsNew = img.load()
for i in range(img.size[0]):
    for j in range(img.size[1]):
    	r,g,b=pixelMap[i,j]
    	pixelsNew[i,j]=(0,0,b)
      

img.save('out.jpg')  
