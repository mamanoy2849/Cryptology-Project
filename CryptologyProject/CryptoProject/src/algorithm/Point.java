package algorithm;


/**
 * @Vincent TC
 * @author William Sentosa
 */
public class Point {
	private long x;
    private long y;
    
    public Point() {
        x = 0;
        y = 0;
    }
    
    public Point(long x, long y) {
        this.x = x;
        this.y = y;
    }
    
    public long getX() {
        return x;
    }
    
    public long getY() {
        return y;
    }
    
    public void setX(long x) {
        this.x = x;
    }
    
    public void setY(long y) {
        this.y = y;
    }
    
    @Override
    public String toString() {
        String result = x + " " + y;
        return result;
    }
    
    public boolean isEqual(Point p) {
        return x==p.x && y==p.y;
    }
    
    
}
